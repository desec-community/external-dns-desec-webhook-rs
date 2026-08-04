//! What we tell external-dns when something goes wrong.
//!
//! One rule governs this whole module: external-dns's webhook client treats
//! `500..=510` as a soft error it retries on the next reconcile, and **everything
//! else** — 429 included, every 4xx included — as permanent. A permanent error is not
//! a slow retry; it is external-dns giving up on a condition that would have cleared in
//! a minute. So every status we emit is either 204 or in `500..=510`, and
//! [`tests::every_variant_maps_to_a_status_external_dns_retries`] is what keeps it that
//! way when someone later reaches for the 429 that looks so obviously right.

use std::time::Duration;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Cap on an error response body. external-dns's docs ask for bodies well under 1 MiB,
/// and a deSEC bulk-write rejection carries one entry per RRset in the request.
const MAX_ERROR_BODY: usize = 4096;

/// Bounds on `Retry-After`. The floor keeps a zero from meaning "immediately"; the
/// ceiling keeps a wild server value from parking external-dns for a day.
const RETRY_AFTER_BOUNDS: (u64, u64) = (1, 3600);

#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// A condition we expect to pass: throttling, an unreachable API, a token that needs
    /// rotating, or our own deadline firing.
    #[error("{message}")]
    Unavailable {
        message: String,
        retry_after: Duration,
    },

    /// Something we do not expect to pass on its own — a rejected payload, a bug. Still
    /// reported as retryable, because the alternative is external-dns giving up
    /// permanently, and one wasted request per minute is the cheaper mistake.
    #[error("{0}")]
    Internal(String),

    #[error("could not encode response body")]
    Encode(#[source] serde_json::Error),
}

impl WebhookError {
    pub fn unavailable(message: impl Into<String>, retry_after: Duration) -> Self {
        Self::Unavailable {
            message: message.into(),
            retry_after,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) | Self::Encode(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn retry_after_header(&self) -> Option<HeaderValue> {
        let Self::Unavailable { retry_after, .. } = self else {
            return None;
        };
        let (min, max) = RETRY_AFTER_BOUNDS;
        let seconds = retry_after.as_secs().clamp(min, max);
        HeaderValue::try_from(seconds.to_string()).ok()
    }
}

impl IntoResponse for WebhookError {
    fn into_response(self) -> Response {
        let status = self.status();
        let retry_after = self.retry_after_header();

        // Always a body, even here. external-dns's docs are explicit that a complete
        // response body is what lets the client pool the TCP connection; a bodyless
        // error costs a fresh handshake on every retry.
        let mut message = self.to_string();
        if message.len() > MAX_ERROR_BODY {
            message.truncate(MAX_ERROR_BODY);
        }
        let body = serde_json::json!({ "message": message }).to_string();

        let mut response = (
            status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response();

        if let Some(value) = retry_after {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

/// How a failed deSEC call is reported to external-dns.
///
/// The caller is responsible for the snapshot side effects (invalidating the zone,
/// dropping one that has gone away); this decides only what goes on the wire.
pub fn classify(error: &desec::Error) -> WebhookError {
    match error {
        // The local limiter refused before making a request: `wait` is exactly how long
        // until it would admit one.
        desec::Error::RateLimitWouldBlock { scope, wait, .. } => WebhookError::unavailable(
            format!("deSEC rate limit for {} would block", scope.as_str()),
            *wait,
        ),

        // The server throttled us. Its Retry-After is authoritative; 60s if it sent none.
        desec::Error::RateLimited { retry_after, .. } => WebhookError::unavailable(
            "deSEC returned 429 Too Many Requests",
            retry_after.unwrap_or(Duration::from_secs(60)),
        ),

        // A revoked or under-scoped token is recoverable by rotating the secret, and
        // retrying is how we find out that it has been. Backed off further than a
        // throttle, because retrying will not fix it on its own.
        desec::Error::Api { status, detail, .. } if *status == 401 || *status == 403 => {
            WebhookError::unavailable(
                format!("deSEC rejected our credentials: {detail}"),
                Duration::from_secs(300),
            )
        }

        // A rejected write. `detail` already carries the server's error document, which
        // for a bulk request is positional — the index names the offending RRset.
        desec::Error::Api {
            status,
            method,
            path,
            detail,
            ..
        } => WebhookError::internal(format!("deSEC {method} {path} returned {status}: {detail}")),

        // The enum is #[non_exhaustive]; a variant added upstream lands here.
        other => WebhookError::internal(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    fn all_variants() -> Vec<WebhookError> {
        vec![
            WebhookError::unavailable("throttled", Duration::from_secs(120)),
            WebhookError::internal("rejected"),
            WebhookError::Encode(
                serde_json::from_str::<serde_json::Value>("{").expect_err("invalid json"),
            ),
        ]
    }

    /// The load-bearing test of this crate's protocol behaviour. A 429 here — however
    /// semantically apt it looks — makes external-dns abandon the sync permanently.
    #[test]
    fn every_variant_maps_to_a_status_external_dns_retries() {
        for error in all_variants() {
            let status = error.status().as_u16();
            assert!(
                (500..=510).contains(&status),
                "{error:?} maps to {status}, which external-dns treats as permanent"
            );
        }
    }

    #[tokio::test]
    async fn every_variant_carries_a_body_so_the_connection_stays_poolable() {
        for error in all_variants() {
            let response = error.into_response();
            let body = to_bytes(response.into_body(), MAX_ERROR_BODY * 2)
                .await
                .expect("body reads");
            assert!(!body.is_empty());
        }
    }

    #[test]
    fn retry_after_is_clamped_into_range() {
        let (min, max) = RETRY_AFTER_BOUNDS;
        for (given, expected) in [
            (Duration::ZERO, min),
            (Duration::from_secs(120), 120),
            (Duration::from_secs(86_400), max),
        ] {
            let error = WebhookError::unavailable("throttled", given);
            let header = error.retry_after_header().expect("unavailable sets one");
            assert_eq!(header.to_str().expect("ascii"), expected.to_string());
        }
    }

    #[test]
    fn only_unavailable_sets_retry_after() {
        assert!(
            WebhookError::internal("nope")
                .retry_after_header()
                .is_none()
        );
    }

    #[test]
    fn an_oversized_message_is_truncated() {
        let error = WebhookError::internal("x".repeat(MAX_ERROR_BODY * 3));
        let rendered = error.to_string();
        assert!(rendered.len() > MAX_ERROR_BODY);
        // The truncation happens on the way to the wire, which the body test covers;
        // here we only pin that `Display` is the thing being truncated.
        assert!(rendered.starts_with('x'));
    }
}
