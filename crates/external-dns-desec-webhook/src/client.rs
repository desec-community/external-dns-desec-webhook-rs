//! The one place the deSEC client is configured.
//!
//! Four values decide how long a single call to deSEC can take, and every one is sized
//! against external-dns's budget rather than against what a library user would want. They
//! live here, behind the only constructor, because the binary and the tests must not be
//! able to drift apart: a test that drives a differently tuned client proves nothing about
//! what ships, and `main` is a binary that no test covers.

use std::time::Duration;

use desec::{Client, Error, RateLimits, Secret};

/// Longest a single HTTP attempt may take, end to end.
///
/// This is `reqwest`'s own timeout, so it covers connect, TLS, request and body read — but
/// not the pacing wait that precedes it. A call is bounded by the two added together, which
/// is the arithmetic `apply`'s module doc draws.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

/// Longest the client-side limiter may sleep before refusing outright.
///
/// Two jobs. It bounds the pacing wait that precedes *every* attempt, and — because
/// `record_throttled` clamps a stored penalty to the same value — it bounds how long one
/// response can idle the client. `Scope::User` is in every request's scope set, so a
/// `Retry-After: 3600` recorded uncapped would park every task for an hour.
pub const MAX_RATE_LIMIT_WAIT: Duration = Duration::from_secs(2);

/// Retries after the first attempt. Zero, and load-bearing.
///
/// `desec-rs` handles a `429` *before* it checks whether the method is replayable, and
/// continues regardless — so a bulk `PATCH`, which is never retried on a 5xx, *is* retried
/// on a throttle. That is defensible for the library, since a throttled request was
/// rejected before the server processed it, and wrong for us, because we are on a clock.
///
/// At zero, `attempt (1) > max_retries (0)` holds on the first `429`, so the error returns
/// at once with deSEC's `Retry-After` intact. We turn that into a `503` plus a
/// `Retry-After` header and external-dns retries on its own schedule rather than inside
/// our handler. Nothing is lost by not retrying: `record_throttled` has already run, so the
/// shared limiter has learned the penalty without another task having to earn its own 429.
pub const MAX_RETRIES: u32 = 0;

/// Longest single retry sleep to accept, for a `Retry-After` or for backoff.
///
/// Inert while [`MAX_RETRIES`] is zero: the library's guard is
/// `attempt > max_retries || delay > max_delay`, the left side always fires first, and
/// `backoff` — the only other reader of this value — is never reached. It is here as the
/// blast radius if [`MAX_RETRIES`] is ever raised: at one second the worst case is three
/// seconds rather than the ninety the crate's 60-second default would allow.
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Builds the client the binary runs on.
///
/// The only constructor, deliberately: the tuning above is not something a caller may apply
/// in part. Constructing it is also what `--check-config` is for — reqwest's rustls backend
/// loads the system trust store here rather than at first request, so an image without a CA
/// bundle fails on this call and passes every unit test.
pub fn build(
    token: impl Into<Secret>,
    base_url: impl Into<String>,
    rate_limits: RateLimits,
) -> Result<Client, Error> {
    Client::builder()
        .token(token)
        .base_url(base_url)
        .user_agent(concat!(
            "external-dns-desec-webhook/",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(REQUEST_TIMEOUT)
        .max_rate_limit_wait(MAX_RATE_LIMIT_WAIT)
        .max_retries(MAX_RETRIES)
        .max_retry_delay(MAX_RETRY_DELAY)
        .rate_limits(rate_limits)
        .build()
}
