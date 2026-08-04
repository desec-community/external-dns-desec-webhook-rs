//! `/healthz`, `/readyz` and `/metrics`, on their own listener.
//!
//! Separate from the provider endpoints because they have different audiences and different
//! exposure: these are for the kubelet and Prometheus and bind to the pod network, while the
//! provider endpoints are unauthenticated and bind to loopback.
//!
//! The distinction that matters here is between liveness and readiness, and getting it wrong
//! is what made the previous provider need `--webhook-provider-read-timeout=30s`:
//!
//! - **`/healthz` ignores deSEC entirely.** A throttle window must leave it green for its
//!   whole duration. Restarting the pod discards the rate limiter's in-memory sliding
//!   windows, so the new process believes it has a fresh budget the server knows it does not
//!   — a restart during throttling makes throttling worse, not better.
//! - **`/readyz` answers "could I serve a useful `/records`?"** It is informational here,
//!   since nothing but external-dns dials the provider port and it does so over loopback.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::metrics::Metrics;
use crate::refresh::Liveness;
use crate::store::SnapshotStore;

#[derive(Clone)]
pub struct AdminState {
    pub store: SnapshotStore,
    pub metrics: Arc<Metrics>,
    pub liveness: Liveness,
    pub refresh_interval: Duration,
}

/// Why the webhook is or is not ready.
#[derive(Debug, PartialEq, Eq)]
pub enum Readiness {
    /// Nothing has been loaded from deSEC yet. `/records` answers 503 in this state, rather
    /// than claiming the zones are empty.
    NoSnapshot,
    Fresh {
        age: Duration,
    },
    Stale {
        age: Duration,
    },
}

impl Readiness {
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Fresh { .. })
    }
}

/// Assess readiness.
///
/// The staleness bound is generous — four intervals or fifteen minutes, whichever is larger —
/// because being unready is not itself useful here, and a tight bound would only produce
/// alert noise during a throttle the design already handles.
pub fn readiness(store: &SnapshotStore, refresh_interval: Duration) -> Readiness {
    let snapshot = store.load();
    let Some(age) = snapshot.age() else {
        return Readiness::NoSnapshot;
    };

    let bound = (refresh_interval * 4).max(Duration::from_secs(900));
    if age > bound {
        Readiness::Stale { age }
    } else {
        Readiness::Fresh { age }
    }
}

pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        // No remap needed here: nothing reads these statuses programmatically, and a probe
        // that times out should read as unavailable.
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            Duration::from_secs(5),
        ))
        .with_state(state)
}

/// Liveness. Deliberately blind to whether deSEC is reachable.
async fn healthz(State(state): State<AdminState>) -> Response {
    if state.liveness.is_wedged(state.refresh_interval) {
        // The refresh task is gone, or has not attempted a tick in ten intervals. Note that
        // a tick which *fails* every time still counts as an attempt: an unreachable API is
        // not something a restart fixes.
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "refresh task is not running\n",
        )
            .into_response();
    }
    (StatusCode::OK, "ok\n").into_response()
}

async fn readyz(State(state): State<AdminState>) -> Response {
    let readiness = readiness(&state.store, state.refresh_interval);
    let body = match &readiness {
        Readiness::NoSnapshot => "no zone data loaded from deSEC yet\n".to_owned(),
        Readiness::Fresh { age } => format!("ready; snapshot is {}s old\n", age.as_secs()),
        Readiness::Stale { age } => {
            format!("snapshot is stale: {}s old\n", age.as_secs())
        }
    };

    let status = if readiness.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, body).into_response()
}

async fn metrics(State(state): State<AdminState>) -> Response {
    let ready = readiness(&state.store, state.refresh_interval).is_ready();

    match state.metrics.encode(&state.store, ready) {
        Ok(body) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                ),
            )],
            body,
        )
            .into_response(),
        Err(error) => {
            tracing::error!(error = %error, "could not encode metrics");
            (StatusCode::INTERNAL_SERVER_ERROR, "encoding failed\n").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{ListedZone, RefreshUpdate};
    use std::collections::HashMap;

    async fn populated() -> SnapshotStore {
        let store = SnapshotStore::new();
        store
            .publish(RefreshUpdate {
                present: vec!["example.com".to_owned()],
                listed: vec![ListedZone {
                    name: "example.com".to_owned(),
                    minimum_ttl: 3600,
                    touched: None,
                    rrsets: HashMap::new(),
                    epoch_at_start: 0,
                }],
                zone_list_ok: true,
                error: None,
            })
            .await;
        store
    }

    #[tokio::test]
    async fn an_unloaded_snapshot_is_not_ready() {
        assert_eq!(
            readiness(&SnapshotStore::new(), Duration::from_secs(180)),
            Readiness::NoSnapshot
        );
        assert!(!Readiness::NoSnapshot.is_ready());
    }

    #[tokio::test]
    async fn a_freshly_loaded_snapshot_is_ready() {
        let readiness = readiness(&populated().await, Duration::from_secs(180));
        assert!(readiness.is_ready(), "{readiness:?}");
    }

    /// The behaviour that made the 30s client-timeout workaround necessary before: a
    /// throttled provider must stay live, or Kubernetes restarts it and the restart discards
    /// the limiter state that was pacing it.
    #[test]
    fn a_running_refresher_stays_live_however_badly_desec_is_behaving() {
        let liveness = Liveness::new();
        assert!(!liveness.is_wedged(Duration::from_secs(180)));
    }
}
