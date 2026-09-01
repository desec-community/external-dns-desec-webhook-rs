//! The four endpoints external-dns calls.
//!
//! Three of them never touch the network. `GET /` answers from configuration, and
//! `GET /records` and `POST /adjustendpoints` answer from the snapshot, so they cannot be
//! made slow by anything deSEC does. Only `POST /records` writes, and it bounds itself.
//!
//! Two axum-specific traps are avoided here deliberately, and both would have been silent:
//!
//! - `axum::Json` as an *extractor* rejects with `415` unless `Content-Type` is
//!   `application/json`. external-dns sends the webhook media type, so using it would make
//!   every single ApplyChanges a permanent failure. Bodies are read as bytes instead.
//! - `tower_http`'s timeout layer answers `408`, which is a 4xx and therefore permanent to
//!   external-dns. It is remapped below.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::adjust;
use crate::apply::Applier;
use crate::convert::{endpoint_from_parts, is_provider_managed};
use crate::error::WebhookError;
use crate::metrics::{EndpointLabel, Metrics, ReasonLabel, op};
use crate::store::SnapshotStore;
use crate::wire::{Changes, DomainFilter, Endpoint, MEDIA_TYPE, WebhookJson};

/// Backstop for a handler that hangs through a bug of ours.
///
/// Inside external-dns's 15s budget and outside the 9s the write path allows itself, so in
/// every expected case our own composed 503 is what the client sees.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone)]
pub struct AppState {
    pub store: SnapshotStore,
    pub applier: Arc<Applier>,
    pub metrics: Arc<Metrics>,
    /// What the negotiate handshake reports. Derived from configuration, never from the API,
    /// so external-dns can start even while deSEC is unreachable — the handshake happens
    /// once and failing it is fatal to external-dns.
    pub filter: DomainFilter,
    pub allow_empty_zone_set: bool,
    pub max_body_bytes: usize,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(negotiate))
        .route("/records", get(records).post(apply_changes))
        .route("/adjustendpoints", post(adjust_endpoints))
        .layer(axum::middleware::map_response(retryable_timeouts))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            // Deliberately the layer's own default status rather than 503 directly: the remap
            // below needs something to recognise, and replaces it with a 503 that carries a
            // body. The 408 never reaches the wire.
            StatusCode::REQUEST_TIMEOUT,
            HANDLER_TIMEOUT,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// Rewrite the timeout layer's `408` into something external-dns will retry, with a body.
///
/// Only `500..=510` is a soft error to external-dns; every other status, `408` included, is
/// permanent. A layer that answered 408 would turn a slow request into an abandoned sync,
/// which is the opposite of what a timeout is for.
async fn retryable_timeouts(response: Response) -> Response {
    if response.status() == StatusCode::REQUEST_TIMEOUT {
        return WebhookError::unavailable(
            "the webhook took too long to answer",
            Duration::from_secs(30),
        )
        .into_response();
    }
    response
}

/// `GET /`: negotiate the zone filter.
async fn negotiate(State(state): State<AppState>) -> WebhookJson<DomainFilter> {
    WebhookJson(state.filter.clone())
}

/// `GET /records`: the current records, from cache.
async fn records(
    State(state): State<AppState>,
) -> Result<WebhookJson<Vec<Endpoint>>, WebhookError> {
    let started = Instant::now();
    let snapshot = state.store.load();

    // An empty array is not "nothing to do", it is a claim that the zone is empty. Every row
    // then takes the `len(row.current) == 0` branch of `plan.calculateChanges`, so external-dns
    // plans a Create for every endpoint it knows about, and the TXT registry re-plans ownership
    // for all of them. A 503 is retried; an empty answer is believed.
    if !snapshot.is_populated() {
        state
            .metrics
            .soft_errors
            .get_or_create(&EndpointLabel {
                endpoint: "records",
            })
            .inc();
        return Err(WebhookError::unavailable(
            "no zone data has been loaded from deSEC yet",
            Duration::from_secs(10),
        ));
    }

    if snapshot.zones.is_empty() && !state.allow_empty_zone_set {
        state
            .metrics
            .soft_errors
            .get_or_create(&EndpointLabel {
                endpoint: "records",
            })
            .inc();
        return Err(WebhookError::unavailable(
            "no managed zones: none of the configured zones exist in this deSEC account",
            Duration::from_secs(60),
        ));
    }

    let mut endpoints = Vec::new();
    for zone in snapshot.zones.zones() {
        for (key, value) in &zone.rrsets {
            // deSEC signs and serves these itself. Reporting them would have external-dns
            // plan a delete for the apex SOA and NS on every cycle, and deSEC would reject
            // every one of them, forever.
            if is_provider_managed(&key.subname, &key.record_type) {
                continue;
            }
            endpoints.push(endpoint_from_parts(
                &zone.name,
                &key.subname,
                &key.record_type,
                value.records(),
                value.ttl,
            ));
        }
    }

    state
        .metrics
        .records_duration
        .observe(started.elapsed().as_secs_f64());
    tracing::debug!(
        endpoints = endpoints.len(),
        zones = snapshot.zones.len(),
        age_s = snapshot.age().map(|age| age.as_secs()),
        "served records from the snapshot"
    );
    Ok(WebhookJson(endpoints))
}

/// `POST /records`: apply changes.
async fn apply_changes(
    State(state): State<AppState>,
    request: Request,
) -> Result<StatusCode, WebhookError> {
    let started = Instant::now();
    let body = read_body(request, state.max_body_bytes).await?;

    let changes: Changes = serde_json::from_slice(&body).map_err(|error| {
        // Reported as retryable rather than as a 400. A 4xx would make external-dns abandon
        // the sync permanently, and the likeliest cause of a body we cannot read is a newer
        // external-dns rather than a broken one.
        tracing::error!(error = %error, "could not decode the change set");
        WebhookError::internal(format!("could not decode changes: {error}"))
    })?;

    let outcome = state.applier.apply(&changes).await;

    state.metrics.record_suppressed(&outcome.report.suppressed);
    // Against the same account-wide budget the refresher's reads come out of, so counted in
    // the same place: 2000 authenticated requests a day covers both.
    for result in &outcome.report.request_outcomes {
        state.metrics.record_desec_request(op::WRITE, result);
    }
    for (zone, rrsets) in &outcome.report.written {
        state.metrics.record_write(zone, "ok", *rrsets);
    }
    // A write we declined to make. Counted because it is the one outcome here that is
    // invisible from outside: no request, so it can never reach `desec_requests_total`, and
    // a 503 that looks like every other 503 in `soft_errors`.
    for (zone, _) in &outcome.report.cooling_down {
        state.metrics.record_write(zone, "cooling_down", 0);
    }
    for normalized in &outcome.report.normalized {
        state.metrics.record_normalized(normalized);
    }
    let result = if outcome.report.timed_out {
        "timeout"
    } else if outcome.error.is_some() {
        "error"
    } else {
        "ok"
    };
    state
        .metrics
        .apply_duration
        .get_or_create(&ReasonLabel { reason: result })
        .observe(started.elapsed().as_secs_f64());

    match outcome.error {
        None => Ok(StatusCode::NO_CONTENT),
        Some(error) => {
            state
                .metrics
                .soft_errors
                .get_or_create(&EndpointLabel { endpoint: "apply" })
                .inc();
            Err(error)
        }
    }
}

/// `POST /adjustendpoints`: normalize what external-dns intends, before it compares it.
async fn adjust_endpoints(
    State(state): State<AppState>,
    request: Request,
) -> Result<WebhookJson<Vec<Endpoint>>, WebhookError> {
    let body = read_body(request, state.max_body_bytes).await?;

    let endpoints: Vec<Endpoint> = serde_json::from_slice(&body).map_err(|error| {
        tracing::error!(error = %error, "could not decode endpoints to adjust");
        WebhookError::internal(format!("could not decode endpoints: {error}"))
    })?;

    let snapshot = state.store.load();
    let (adjusted, tally) = adjust::adjust(endpoints, &snapshot.zones);
    state.metrics.record_adjustments(&tally);

    tracing::debug!(
        returned = adjusted.len(),
        dropped = tally.dropped(),
        ttl_clamped = tally.ttl_clamped,
        "adjusted endpoints"
    );
    Ok(WebhookJson(adjusted))
}

/// Read a request body under an explicit cap.
///
/// Hand-rolled rather than using the `Bytes` extractor with `DefaultBodyLimit`, because that
/// rejects with `413` — a 4xx, and therefore permanent. The cap is well above axum's 2 MiB
/// default: a large cluster's `/adjustendpoints` payload runs to tens of megabytes.
async fn read_body(request: Request, limit: usize) -> Result<axum::body::Bytes, WebhookError> {
    if let Some(accept) = request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
    {
        // Never routed on and never rejected. A guard that 404s on a missing or unexpected
        // Accept is a permanent failure, and external-dns sends none at all on ApplyChanges.
        if !accept.contains(MEDIA_TYPE) && !accept.contains("*/*") {
            tracing::warn!(accept, "unrecognised Accept header; answering anyway");
        }
    }

    axum::body::to_bytes(request.into_body(), limit)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, limit, "could not read the request body");
            WebhookError::internal(format!("could not read request body: {error}"))
        })
}
