//! `POST /records`: the only endpoint that talks to deSEC.
//!
//! It has 15 seconds, once, and no retry within the cycle — that is external-dns's whole
//! budget for a round trip, and overrunning it is what took external-dns down before. So
//! the deadlines here nest inside each other, roughly three seconds apart, and the outermost
//! one is still comfortably inside external-dns's:
//!
//! ```text
//! 15s  external-dns client budget (--webhook-provider-read-timeout + --write-timeout)
//!  └ 12s  tower::TimeoutLayer on the router          hard backstop
//!     └ 9s  the deadline below                       so *we* choose the failure mode
//!        └ 6s  one deSEC call: 2s pacing wait + 4s request
//! ```
//!
//! The innermost line is two of `client`'s constants added together, not one: the limiter
//! sleeps before `reqwest`'s timeout window opens rather than inside it. The gate below
//! sits outside all of this.
//!
//! Choosing our own failure mode is the point. We answer 503 with a body and a
//! `Retry-After` on a connection the client can reuse, rather than letting it time out and
//! classify a torn connection as a transport error.
//!
//! The cooldown is the other half of that. Answering fast is not the same as not asking:
//! external-dns reads the status code and nothing else, so it comes back on its own
//! `--interval` whatever `Retry-After` we sent, and a zone that earns a 429 would earn
//! another one every cycle. So a zone deSEC has just refused is not asked again until the
//! wait it named elapses. external-dns sees the same 503 either way; deSEC sees one request
//! per cooldown instead of one per minute.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use desec::api::rrsets::BulkPatch;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::error::{WebhookError, classify};
use crate::model::RrKey;
use crate::plan::{self, ZonePlan};
use crate::store::SnapshotStore;
use crate::wire::Changes;

/// How long the whole handler may take. Inside the router's own timeout, so a 503 we
/// compose always beats the bodyless one the layer would produce.
pub const DEADLINE: Duration = Duration::from_secs(9);

/// How many zones may be written at once.
///
/// Each zone has its own `dns_api_per_domain_expensive` bucket, so they do not contend with
/// each other on the rate limiter; the cap is only about not opening an unbounded number of
/// connections on a large account.
const FAN_OUT: usize = 8;

/// What `Retry-After` to offer when our own deadline is what failed.
const DEADLINE_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Zones deSEC has refused a write to, and until when.
///
/// The limiter inside `desec-rs` cannot do this job. It clamps a stored penalty to
/// `max_wait` — 2s here, and deliberately, because that same value is how long `acquire`
/// may sleep — so two seconds after a 429 it believes the account is admissible again.
/// This is that memory, kept where it matters, for as long as deSEC said.
#[derive(Clone)]
struct Cooldown {
    until: Arc<Mutex<HashMap<String, Instant>>>,
    /// Longest to believe one response. Zero disables the whole thing.
    cap: Duration,
}

impl Cooldown {
    fn new(cap: Duration) -> Self {
        Self {
            until: Arc::new(Mutex::new(HashMap::new())),
            cap,
        }
    }

    /// How long is left, if this zone is still cooling down.
    ///
    /// A lapsed entry is dropped here rather than left for the next write, so a zone that
    /// is throttled once and then goes quiet does not keep an entry for the life of the
    /// process.
    fn remaining(&self, zone: &str) -> Option<Duration> {
        let mut until = self.until.lock().expect("cooldown mutex");
        let deadline = *until.get(zone)?;
        match deadline.checked_duration_since(Instant::now()) {
            Some(left) if !left.is_zero() => Some(left),
            _ => {
                until.remove(zone);
                None
            }
        }
    }

    /// Remember that deSEC refused a write to this zone, for as long as it said.
    fn record(&self, zone: &str, wait: Duration) {
        if self.cap.is_zero() {
            return;
        }
        let Some(deadline) = Instant::now().checked_add(wait.min(self.cap)) else {
            return;
        };
        self.until
            .lock()
            .expect("cooldown mutex")
            .insert(zone.to_owned(), deadline);
    }

    /// Forget a zone: its write landed, or it is gone from the account.
    fn clear(&self, zone: &str) {
        self.until.lock().expect("cooldown mutex").remove(zone);
    }
}

#[derive(Debug, Default)]
pub struct ApplyReport {
    /// Changes that became no requests, by reason.
    pub suppressed: plan::Tally,
    /// Zone name and how many RRsets its one request carried.
    pub written: Vec<(String, usize)>,
    /// Zones left alone because deSEC refused them recently, and how long is left. No
    /// request was made for any of these.
    pub cooling_down: Vec<(String, Duration)>,
    pub zones_failed: usize,
    /// True when our own deadline fired rather than a request failing.
    pub timed_out: bool,
}

impl ApplyReport {
    pub fn requests(&self) -> usize {
        self.written.len()
    }
}

/// Per-zone outcomes, collected by the tasks themselves so a fired deadline cannot discard
/// the knowledge of which zones already succeeded.
type ZoneResults = Arc<Mutex<Vec<(String, Result<usize, WebhookError>)>>>;

/// The outcome of an apply, carrying both what to report to external-dns and what to
/// record as metrics — the two are needed on both the success and failure paths.
#[derive(Debug)]
pub struct ApplyOutcome {
    pub report: ApplyReport,
    /// `None` means answer 204.
    pub error: Option<WebhookError>,
}

pub struct Applier {
    client: desec::Client,
    store: SnapshotStore,
    dry_run: bool,
    /// Zones deSEC has already refused, so we do not spend a request finding out again.
    cooldown: Cooldown,
    /// Serializes applies against each other.
    ///
    /// external-dns should not overlap two reconciles, but if it does, two handlers
    /// diffing against the same snapshot would each plan the same write.
    gate: Arc<tokio::sync::Mutex<()>>,
}

impl Applier {
    pub fn new(
        client: desec::Client,
        store: SnapshotStore,
        dry_run: bool,
        cooldown_cap: Duration,
    ) -> Self {
        Self {
            client,
            store,
            dry_run,
            cooldown: Cooldown::new(cooldown_cap),
            gate: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub async fn apply(&self, changes: &Changes) -> ApplyOutcome {
        let _gate = self.gate.lock().await;

        let snapshot = self.store.load();
        let plan = plan::build(changes, &snapshot.zones);

        tracing::debug!(
            zones = plan.zones.len(),
            rrsets = plan.rrset_count(),
            suppressed = plan.tally.suppressed(),
            "planned changes"
        );

        if plan.is_empty() {
            // The common case on a settled cluster, and the whole point of the suppression:
            // external-dns asked for something, and it cost no quota.
            return ApplyOutcome {
                report: ApplyReport {
                    suppressed: plan.tally,
                    ..ApplyReport::default()
                },
                error: None,
            };
        }

        if self.dry_run {
            for zone in &plan.zones {
                tracing::info!(
                    zone = %zone.zone,
                    rrsets = zone.patches.len(),
                    "dry run: not writing"
                );
            }
            return ApplyOutcome {
                report: ApplyReport {
                    suppressed: plan.tally,
                    ..ApplyReport::default()
                },
                error: None,
            };
        }

        let mut writable = Vec::new();
        let mut cooling = Vec::new();
        for zone in plan.zones {
            match self.cooldown.remaining(&zone.zone) {
                Some(wait) => {
                    tracing::info!(
                        zone = %zone.zone,
                        rrsets = zone.patches.len(),
                        wait_s = wait.as_secs(),
                        "still cooling down after a deSEC throttle; not writing"
                    );
                    cooling.push((zone.zone, wait));
                }
                None => writable.push(zone),
            }
        }

        // Only what we actually attempt. A cooling zone has to stay out of this, or the
        // deadline path below invalidates a zone nothing touched and buys a forced re-list
        // while the account is throttled.
        let attempted: Vec<String> = writable.iter().map(|zone| zone.zone.clone()).collect();

        // Seeded with the cooling zones, so the loop below reports them without knowing they
        // are special: it already prefers an error carrying a wait over a rejection.
        let results: ZoneResults = Arc::new(Mutex::new(
            cooling
                .iter()
                .map(|(zone, wait)| {
                    let reported = WebhookError::unavailable(
                        format!(
                            "deSEC throttled writes to {zone}; not asking again for {}s",
                            wait.as_secs()
                        ),
                        *wait,
                    );
                    (zone.clone(), Err(reported))
                })
                .collect(),
        ));

        let timed_out = tokio::time::timeout(DEADLINE, self.write_all(writable, &results))
            .await
            .is_err();

        let mut report = ApplyReport {
            suppressed: plan.tally,
            cooling_down: cooling,
            timed_out,
            ..ApplyReport::default()
        };
        let mut error = None;

        let finished = std::mem::take(&mut *results.lock().expect("results mutex"));
        for (zone, outcome) in finished {
            match outcome {
                Ok(rrsets) => report.written.push((zone, rrsets)),
                Err(reported) => {
                    report.zones_failed += 1;
                    // Prefer a throttle over a rejection when reporting: it tells
                    // external-dns how long to wait, which is more actionable than which
                    // record deSEC disliked.
                    let prefer = reported.retry_after().is_some()
                        && error
                            .as_ref()
                            .is_none_or(|e: &WebhookError| e.retry_after().is_none());
                    if error.is_none() || prefer {
                        error = Some(reported);
                    }
                }
            }
        }

        if timed_out {
            let written: Vec<&String> = report.written.iter().map(|(zone, _)| zone).collect();
            for zone in &attempted {
                if !written.contains(&zone) {
                    // No rollback. external-dns's docs say not to assume one is needed, and
                    // it would cost another write against the per-zone daily budget. Marking
                    // the zone untrusted is enough: the next refresh reads what actually
                    // landed.
                    self.store.invalidate(zone).await;
                }
            }
            tracing::warn!(
                written = report.written.len(),
                attempted = attempted.len(),
                "apply hit its deadline; reporting a retryable error with partial progress"
            );
            error = Some(WebhookError::unavailable(
                "timed out applying changes to deSEC",
                DEADLINE_RETRY_AFTER,
            ));
        }

        ApplyOutcome { report, error }
    }

    /// Write every zone concurrently, each recording its own outcome as it completes.
    ///
    /// The recording happens *inside* each task rather than after joining, because this
    /// future is dropped when the deadline fires — collecting afterwards would throw away
    /// the knowledge of which zones succeeded, and we would then invalidate zones whose
    /// writes had already landed.
    async fn write_all(&self, zones: Vec<ZonePlan>, results: &ZoneResults) {
        let permits = Arc::new(Semaphore::new(FAN_OUT));
        let mut tasks = JoinSet::new();

        for zone in zones {
            let client = self.client.clone();
            let store = self.store.clone();
            let cooldown = self.cooldown.clone();
            let permits = Arc::clone(&permits);
            let results = Arc::clone(results);

            tasks.spawn(async move {
                let Ok(_permit) = permits.acquire().await else {
                    return;
                };
                let outcome = write_zone(&client, &store, &cooldown, &zone).await;
                results
                    .lock()
                    .expect("results mutex")
                    .push((zone.zone, outcome));
            });
        }

        while tasks.join_next().await.is_some() {}
    }
}

/// One zone, one atomic request.
///
/// The caller has already checked the cooldown; this is what records into it.
async fn write_zone(
    client: &desec::Client,
    store: &SnapshotStore,
    cooldown: &Cooldown,
    plan: &ZonePlan,
) -> Result<usize, WebhookError> {
    let rrsets = plan.patches.len();
    tracing::debug!(zone = %plan.zone, rrsets, "writing");

    match client.rrsets(&plan.zone).patch_bulk(&plan.patches).await {
        Ok(confirmed) => {
            // Whatever deSEC said before, it is writing now.
            cooldown.clear(&plan.zone);
            store
                .apply_confirmed(&plan.zone, &confirmed, &plan.deleted)
                .await;
            Ok(rrsets)
        }
        Err(error) => {
            let reported = classify(&error);

            // First, and before any await: this runs in a task the deadline can drop, and
            // that deSEC refused us is the thing least worth losing.
            //
            // Matched on the variant rather than through `error.is_rate_limited()`, which is
            // also true for `RateLimitWouldBlock` — our own limiter declining before a
            // request exists, so nothing was refused and there is nothing to remember. It
            // also keeps out the 300s `classify` gives a 401/403, where retrying is how we
            // find out the secret has been rotated.
            //
            // The wait comes from `reported`, so what we remember and what we tell
            // external-dns cannot drift — including the 60s substituted for a bare 429.
            if matches!(error, desec::Error::RateLimited { .. }) {
                if let Some(wait) = reported.retry_after() {
                    cooldown.record(&plan.zone, wait);
                }
            }

            if error.is_not_found() {
                // The zone is gone from the account. Keeping it would wedge the cycle:
                // external-dns goes on planning changes for it, and every write 404s.
                tracing::warn!(zone = %plan.zone, "zone no longer exists; dropping it");
                store.forget(&plan.zone).await;
                cooldown.clear(&plan.zone);
            } else {
                store.invalidate(&plan.zone).await;
            }

            tracing::warn!(
                zone = %plan.zone,
                rrsets,
                error = %error,
                retry_after_s = reported.retry_after().map(|wait| wait.as_secs()),
                patches = %describe(&plan.patches),
                "write failed"
            );
            Err(reported)
        }
    }
}

/// The RRsets a request addressed, for a log line that can be matched against deSEC's
/// positional error document.
fn describe(patches: &[BulkPatch]) -> String {
    patches
        .iter()
        .map(|patch| {
            let (subname, record_type) = plan::patch_key(patch);
            format!("{}/{}", subname, record_type.as_str())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The RRsets a plan removes, exposed for the snapshot update in tests.
pub fn deletions(plan: &ZonePlan) -> &[RrKey] {
    &plan.deleted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RrValue, Zone};
    use crate::store::{ListedZone, RefreshUpdate};
    use crate::wire::{Endpoint, RecordTypeName, Ttl};
    use std::collections::HashMap;
    use std::time::Instant;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// What `--max-throttle-cooldown` defaults to. Long enough that any test making two
    /// applies sees the second one declined; `config::tests` pins the default itself.
    const COOLDOWN: Duration = Duration::from_secs(3600);

    /// The client the binary builds, pointed at a mock. Going through `crate::client`
    /// rather than a builder chain of its own is the point: these tests cannot run a
    /// configuration that differs from the shipped one.
    fn client(server: &MockServer) -> desec::Client {
        crate::client::build(
            "i-T3b1h_OI-H9ab8tRS98stGtURe",
            format!("{}/api/v1", server.uri()),
            desec::RateLimits::desec_defaults(),
        )
        .expect("builds")
    }

    async fn store_with(rrsets: &[(&str, &str, u32, &[&str])]) -> SnapshotStore {
        let store = SnapshotStore::new();
        store
            .publish(RefreshUpdate {
                present: vec!["example.com".to_owned()],
                listed: vec![ListedZone {
                    name: "example.com".to_owned(),
                    minimum_ttl: 3600,
                    touched: None,
                    rrsets: rrsets
                        .iter()
                        .map(|(subname, record_type, ttl, records)| {
                            (
                                RrKey::new(
                                    subname.parse().expect("valid subname"),
                                    record_type.parse().expect("valid type"),
                                ),
                                RrValue::new(records.iter().map(|r| (*r).to_owned()), *ttl),
                            )
                        })
                        .collect(),
                    epoch_at_start: 0,
                }],
                zone_list_ok: true,
                error: None,
            })
            .await;
        store
    }

    fn endpoint(dns_name: &str, record_type: &str, targets: &[&str]) -> Endpoint {
        Endpoint {
            dns_name: dns_name.to_owned(),
            targets: targets.iter().map(|t| (*t).to_owned()).collect(),
            record_type: RecordTypeName::new(record_type),
            record_ttl: Ttl(3600),
            ..Endpoint::default()
        }
    }

    #[tokio::test]
    async fn a_change_that_matches_stored_state_makes_no_request() {
        let server = MockServer::start().await;
        // Any request at all is a failure of the suppression.
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let store = store_with(&[("www", "A", 3600, &["192.0.2.1"])]).await;
        let applier = Applier::new(client(&server), store, false, COOLDOWN);

        let outcome = applier
            .apply(&Changes {
                update_new: vec![endpoint("www.example.com", "A", &["192.0.2.1"])],
                ..Changes::default()
            })
            .await;

        assert!(outcome.error.is_none());
        assert_eq!(outcome.report.requests(), 0);
        assert_eq!(outcome.report.suppressed.identical, 1);
        server.verify().await;
    }

    #[tokio::test]
    async fn a_retype_is_one_request_carrying_both_rrsets() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/domains/example.com/rrsets/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&server)
            .await;

        let store = store_with(&[("www", "A", 3600, &["192.0.2.1"])]).await;
        let applier = Applier::new(client(&server), store, false, COOLDOWN);

        let outcome = applier
            .apply(&Changes {
                create: vec![endpoint(
                    "www.example.com",
                    "CNAME",
                    &["target.example.org"],
                )],
                delete: vec![endpoint("www.example.com", "A", &["192.0.2.1"])],
                ..Changes::default()
            })
            .await;

        assert!(outcome.error.is_none());
        assert_eq!(outcome.report.written, vec![("example.com".to_owned(), 2)]);
        server.verify().await;
    }

    /// The test that most distinguishes this provider from the one it replaces.
    ///
    /// One property, asserted of every `Retry-After` deSEC can send: the write reaches deSEC
    /// **once**, and external-dns gets an answer it can act on well inside its budget. A
    /// throttled request is rejected before the server processes it, so replaying it is safe
    /// as far as the API is concerned — and the library does replay it, because it handles a
    /// 429 before checking whether the method is replayable. Waiting is external-dns's job,
    /// not ours; it has no deadline and we have fifteen seconds, once.
    ///
    /// The values straddle [`crate::client::MAX_RETRY_DELAY`], because that is where the
    /// library's behaviour changes. Its guard is `attempt > max_retries || delay > max_delay`,
    /// so anything above the ceiling returns at once whatever the retry count says, and only
    /// the values at or below it can observe the retry count at all. At `Retry-After: 1`,
    /// three retries would be four requests and three seconds; a single 30s case would not
    /// notice.
    ///
    /// Timed against the wall clock rather than under `start_paused`: tokio auto-advances
    /// paused time whenever every task is idle, and a task awaiting a real socket looks
    /// idle, so the client's own timeout fires instantly and the request never completes.
    #[tokio::test]
    async fn a_throttled_write_reaches_desec_once_whatever_retry_after_says() {
        // `None` is the bare 429 an intermediary sends; `classify` supplies 60s for it.
        for (retry_after, expected) in [
            (None, 60),
            (Some(1), 1),
            (Some(30), 30),
            (Some(60), 60),
            (Some(3600), 3600),
        ] {
            let server = MockServer::start().await;
            let mut response = ResponseTemplate::new(429)
                .set_body_json(serde_json::json!({"detail": "Request was throttled."}));
            if let Some(seconds) = retry_after {
                response = response.insert_header("Retry-After", seconds.to_string().as_str());
            }
            // A fresh server and client each round, so one round's recorded penalty cannot
            // pace the next one and make it look fast for the wrong reason.
            Mock::given(method("PATCH"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;

            let store = store_with(&[]).await;
            let applier = Applier::new(client(&server), store, false, COOLDOWN);

            let started = Instant::now();
            let outcome = applier
                .apply(&Changes {
                    create: vec![endpoint("new.example.com", "A", &["192.0.2.1"])],
                    ..Changes::default()
                })
                .await;
            let elapsed = started.elapsed();

            // Before the assertions below, so a replayed write is diagnosed as the extra
            // requests it is rather than as the seconds they took.
            server.verify().await;

            let error = outcome.error.expect("throttling is reported");
            assert_eq!(error.status().as_u16(), 503, "never 429: that is permanent");
            assert_eq!(
                error.retry_after(),
                Some(Duration::from_secs(expected)),
                "Retry-After {retry_after:?} should reach external-dns as {expected}s"
            );
            assert!(
                elapsed < Duration::from_secs(2),
                "Retry-After {retry_after:?} answered in {elapsed:?}; external-dns allows 15s \
                 for the whole round trip, once"
            );
            assert!(!outcome.report.timed_out);
        }
    }

    /// The test of the cooldown, and the one that is red without it.
    ///
    /// external-dns reads only the status code of our answer, so it returns every
    /// `--interval` whatever `Retry-After` we sent. Before this, each of those cycles spent
    /// another bulk PATCH that could only be refused, against a budget of 300 a day.
    #[tokio::test]
    async fn a_second_apply_after_a_throttle_costs_no_request_until_the_cooldown_lapses() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "300")
                    .set_body_json(serde_json::json!({"detail": "Request was throttled."})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let store = store_with(&[]).await;
        // One applier across both applies: the cooldown lives here, and two reconciles
        // against one process is exactly the case.
        let applier = Applier::new(client(&server), store, false, COOLDOWN);
        let changes = Changes {
            create: vec![endpoint("new.example.com", "A", &["192.0.2.1"])],
            ..Changes::default()
        };

        let first = applier.apply(&changes).await;
        let second = applier.apply(&changes).await;

        server.verify().await;

        assert_eq!(
            first.error.expect("throttled").retry_after(),
            Some(Duration::from_secs(300))
        );
        let error = second.error.expect("still declined");
        assert_eq!(error.status().as_u16(), 503, "external-dns sees no change");
        let left = error.retry_after().expect("says how long is left");
        assert!(
            left <= Duration::from_secs(300) && !left.is_zero(),
            "counts down from deSEC's own wait, got {left:?}"
        );
        assert_eq!(second.report.cooling_down.len(), 1);
        assert_eq!(second.report.requests(), 0);
    }

    /// The counterpart: the cooldown lets go on its own, without anything clearing it.
    #[tokio::test]
    async fn a_zone_whose_cooldown_has_lapsed_is_written_on_the_next_apply() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "1")
                    .set_body_json(serde_json::json!({"detail": "Request was throttled."})),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&server)
            .await;

        let store = store_with(&[]).await;
        let applier = Applier::new(client(&server), store, false, COOLDOWN);
        let changes = Changes {
            create: vec![endpoint("new.example.com", "A", &["192.0.2.1"])],
            ..Changes::default()
        };

        assert!(applier.apply(&changes).await.error.is_some());
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let after = applier.apply(&changes).await;

        server.verify().await;
        assert!(after.error.is_none(), "the write is attempted again");
        assert_eq!(after.report.requests(), 1);
    }

    /// Only a server throttle earns a cooldown.
    ///
    /// `error.is_rate_limited()` is the helper this reaches past, and it is wrong twice
    /// over: it is true for `RateLimitWouldBlock`, which is our own limiter declining before
    /// a request exists, and going through the classified error instead would pick up the
    /// 300s a 401/403 carries — where retrying is precisely how we find out that the secret
    /// has been rotated.
    #[tokio::test]
    async fn a_failure_that_is_not_a_server_throttle_does_not_gate_the_next_write() {
        for status in [400, 401, 403, 500] {
            let server = MockServer::start().await;
            Mock::given(method("PATCH"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_json(serde_json::json!({"detail": "nope"})),
                )
                .expect(2)
                .mount(&server)
                .await;

            let store = store_with(&[]).await;
            let applier = Applier::new(client(&server), store, false, COOLDOWN);
            let changes = Changes {
                create: vec![endpoint("new.example.com", "A", &["192.0.2.1"])],
                ..Changes::default()
            };

            applier.apply(&changes).await;
            let second = applier.apply(&changes).await;

            server.verify().await;
            assert!(
                second.report.cooling_down.is_empty(),
                "{status} must not cool the zone down"
            );
        }
    }

    /// A 429 names no scope, so it is evidence about the zone that earned it and nothing
    /// else. Cooling a zone that never failed would trade availability for budget.
    #[tokio::test]
    async fn a_throttle_on_one_zone_does_not_silence_another() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/domains/a.example.com/rrsets/"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "300")
                    .set_body_json(serde_json::json!({"detail": "Request was throttled."})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/domains/b.example.com/rrsets/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(2)
            .mount(&server)
            .await;

        let store = SnapshotStore::new();
        store
            .publish(RefreshUpdate {
                present: vec!["a.example.com".to_owned(), "b.example.com".to_owned()],
                listed: ["a.example.com", "b.example.com"]
                    .into_iter()
                    .map(|name| ListedZone {
                        name: name.to_owned(),
                        minimum_ttl: 3600,
                        touched: None,
                        rrsets: HashMap::new(),
                        epoch_at_start: 0,
                    })
                    .collect(),
                zone_list_ok: true,
                error: None,
            })
            .await;

        let applier = Applier::new(client(&server), store, false, COOLDOWN);
        let changes = Changes {
            create: vec![
                endpoint("x.a.example.com", "A", &["192.0.2.1"]),
                endpoint("x.b.example.com", "A", &["192.0.2.1"]),
            ],
            ..Changes::default()
        };

        applier.apply(&changes).await;
        let second = applier.apply(&changes).await;

        server.verify().await;
        assert_eq!(
            second.report.cooling_down,
            vec![("a.example.com".to_owned(), second.report.cooling_down[0].1)],
            "only the zone that earned the 429"
        );
    }

    /// A cooling zone was not attempted, so nothing about it may be touched.
    ///
    /// Asserted on the snapshot generation rather than on `touched`, which the first 429's
    /// own invalidation has already cleared: the claim is that the second apply mutates the
    /// store not at all, and a forced re-list is a read request spent on a zone we
    /// deliberately did not write while the account is throttled.
    #[tokio::test]
    async fn a_zone_that_is_cooling_down_is_not_invalidated_because_nothing_was_attempted() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "300")
                    .set_body_json(serde_json::json!({"detail": "Request was throttled."})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let store = store_with(&[]).await;
        let applier = Applier::new(client(&server), store.clone(), false, COOLDOWN);
        let changes = Changes {
            create: vec![endpoint("new.example.com", "A", &["192.0.2.1"])],
            ..Changes::default()
        };

        applier.apply(&changes).await;
        let settled = store.load().generation;
        applier.apply(&changes).await;

        server.verify().await;
        assert_eq!(store.load().generation, settled, "no store write at all");
    }

    /// A dry run makes no request, so it can never be throttled and must never be declined.
    #[tokio::test]
    async fn a_dry_run_is_never_cooled_down_because_it_never_asks() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(429))
            .expect(0)
            .mount(&server)
            .await;

        let store = store_with(&[]).await;
        let applier = Applier::new(client(&server), store, true, COOLDOWN);
        let changes = Changes {
            create: vec![endpoint("new.example.com", "A", &["192.0.2.1"])],
            ..Changes::default()
        };

        assert!(applier.apply(&changes).await.error.is_none());
        assert!(applier.apply(&changes).await.error.is_none());
        server.verify().await;
    }

    #[test]
    fn a_cooldown_lapses_on_its_own_without_anything_clearing_it() {
        let cooldown = Cooldown::new(COOLDOWN);
        cooldown.record("example.com", Duration::from_millis(50));
        assert!(cooldown.remaining("example.com").is_some());

        std::thread::sleep(Duration::from_millis(80));

        assert!(cooldown.remaining("example.com").is_none());
        assert!(
            cooldown.until.lock().expect("cooldown mutex").is_empty(),
            "a zone throttled once and then quiet leaves no entry behind"
        );
    }

    #[test]
    fn a_cooldown_offers_the_time_that_is_left_rather_than_the_time_it_started_with() {
        let cooldown = Cooldown::new(COOLDOWN);
        cooldown.record("example.com", Duration::from_secs(300));
        std::thread::sleep(Duration::from_millis(20));

        let left = cooldown.remaining("example.com").expect("still cooling");
        assert!(
            left < Duration::from_secs(300) && left > Duration::from_secs(299),
            "counts down, got {left:?}"
        );
    }

    #[test]
    fn a_cooldown_never_outlasts_its_ceiling_whatever_desec_says() {
        let cooldown = Cooldown::new(Duration::from_secs(3600));
        // 24h is desec-rs's own clamp on the header, so the largest value that can reach us.
        cooldown.record("example.com", Duration::from_secs(86_400));

        let left = cooldown.remaining("example.com").expect("still cooling");
        assert!(left <= Duration::from_secs(3600), "capped, got {left:?}");
    }

    #[test]
    fn a_disabled_cooldown_remembers_nothing() {
        let cooldown = Cooldown::new(Duration::ZERO);
        cooldown.record("example.com", Duration::from_secs(300));
        assert!(cooldown.remaining("example.com").is_none());
    }

    #[tokio::test]
    async fn a_rejected_write_invalidates_the_zone_rather_than_trusting_the_cache() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!([
                {},
                {"records": ["Invalid record."]}
            ])))
            .mount(&server)
            .await;

        let store = store_with(&[("www", "A", 3600, &["192.0.2.1"])]).await;
        let applier = Applier::new(client(&server), store.clone(), false, COOLDOWN);

        let outcome = applier
            .apply(&Changes {
                create: vec![endpoint("new.example.com", "A", &["192.0.2.1"])],
                ..Changes::default()
            })
            .await;

        let error = outcome.error.expect("a rejection is reported");
        assert_eq!(error.status().as_u16(), 500);
        // deSEC reports bulk failures positionally, and the index survives into the message.
        assert!(error.to_string().contains("1.records"), "{error}");
        assert!(
            store
                .load()
                .zones
                .get("example.com")
                .expect("still served")
                .touched
                .is_none(),
            "a zone we tried to write must not go on claiming to know its own contents"
        );
    }

    #[tokio::test]
    async fn a_zone_that_has_gone_away_is_dropped_not_retried_forever() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "detail": "Not found."
            })))
            .mount(&server)
            .await;

        let store = store_with(&[]).await;
        let applier = Applier::new(client(&server), store.clone(), false, COOLDOWN);

        applier
            .apply(&Changes {
                create: vec![endpoint("new.example.com", "A", &["192.0.2.1"])],
                ..Changes::default()
            })
            .await;

        assert!(store.load().zones.get("example.com").is_none());
    }

    #[tokio::test]
    async fn a_confirmed_write_is_visible_to_the_next_read_without_waiting_for_a_refresh() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "domain": "example.com",
                    "subname": "new",
                    "type": "A",
                    "name": "new.example.com.",
                    "records": ["192.0.2.1"],
                    "ttl": 3600,
                    "created": "2026-01-01T00:00:00Z",
                    "touched": "2026-01-01T00:00:00Z",
                }])),
            )
            .mount(&server)
            .await;

        let store = store_with(&[]).await;
        let applier = Applier::new(client(&server), store.clone(), false, COOLDOWN);

        applier
            .apply(&Changes {
                create: vec![endpoint("new.example.com", "A", &["192.0.2.1"])],
                ..Changes::default()
            })
            .await;

        // Without this, the next reconcile would diff against pre-write state and plan the
        // same change again — a write loop with a 180-second period.
        let snapshot = store.load();
        let zone = snapshot.zones.get("example.com").expect("present");
        assert_eq!(zone.rrsets.len(), 1);
        assert_eq!(zone.write_epoch, 1);
    }

    #[tokio::test]
    async fn a_dry_run_makes_no_request_but_still_reports_what_it_would_do() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let store = store_with(&[]).await;
        let applier = Applier::new(client(&server), store, true, COOLDOWN);

        let outcome = applier
            .apply(&Changes {
                create: vec![endpoint("new.example.com", "A", &["192.0.2.1"])],
                ..Changes::default()
            })
            .await;

        assert!(outcome.error.is_none());
        assert_eq!(outcome.report.requests(), 0);
        server.verify().await;
    }

    #[tokio::test]
    async fn changes_for_no_managed_zone_are_skipped_without_failing_the_rest() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&server)
            .await;

        let store = store_with(&[]).await;
        let applier = Applier::new(client(&server), store, false, COOLDOWN);

        let outcome = applier
            .apply(&Changes {
                create: vec![
                    // The apex ownership artefact: a sibling of the zone under .com.
                    endpoint(
                        "externaldns-a-example.com",
                        "TXT",
                        &["heritage=external-dns"],
                    ),
                    endpoint("ok.example.com", "A", &["192.0.2.1"]),
                ],
                ..Changes::default()
            })
            .await;

        assert!(
            outcome.error.is_none(),
            "the placeable change still applies"
        );
        assert_eq!(outcome.report.suppressed.no_managed_zone, 1);
        server.verify().await;
    }

    /// Zones do not contend on the rate limiter — each has its own per-domain bucket — so
    /// a multi-zone apply is one request per zone, concurrently.
    #[tokio::test]
    async fn each_zone_gets_exactly_one_request() {
        let server = MockServer::start().await;
        for zone in ["a.example.com", "b.example.com"] {
            Mock::given(method("PATCH"))
                .and(path(format!("/api/v1/domains/{zone}/rrsets/")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
                .expect(1)
                .mount(&server)
                .await;
        }

        let store = SnapshotStore::new();
        store
            .publish(RefreshUpdate {
                present: vec!["a.example.com".to_owned(), "b.example.com".to_owned()],
                listed: ["a.example.com", "b.example.com"]
                    .into_iter()
                    .map(|name| ListedZone {
                        name: name.to_owned(),
                        minimum_ttl: 3600,
                        touched: None,
                        rrsets: HashMap::new(),
                        epoch_at_start: 0,
                    })
                    .collect(),
                zone_list_ok: true,
                error: None,
            })
            .await;

        let applier = Applier::new(client(&server), store, false, COOLDOWN);
        let outcome = applier
            .apply(&Changes {
                create: vec![
                    endpoint("x.a.example.com", "A", &["192.0.2.1"]),
                    endpoint("x.b.example.com", "A", &["192.0.2.1"]),
                ],
                ..Changes::default()
            })
            .await;

        assert!(outcome.error.is_none());
        assert_eq!(outcome.report.requests(), 2);
        server.verify().await;
    }

    #[tokio::test]
    async fn an_unlisted_zone_is_not_written_to() {
        // A zone we know exists but have never read. Writing into it would mean planning
        // against records we have not seen.
        let store = SnapshotStore::new();
        store
            .publish(RefreshUpdate {
                present: vec!["example.com".to_owned()],
                listed: Vec::new(),
                zone_list_ok: true,
                error: None,
            })
            .await;

        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let applier = Applier::new(client(&server), store, false, COOLDOWN);
        let outcome = applier
            .apply(&Changes {
                create: vec![endpoint("new.example.com", "A", &["192.0.2.1"])],
                ..Changes::default()
            })
            .await;

        assert_eq!(outcome.report.suppressed.no_managed_zone, 1);
        server.verify().await;
    }

    #[test]
    fn a_zone_plan_names_its_rrsets_for_the_failure_log() {
        let zone = Zone {
            name: "example.com".to_owned(),
            minimum_ttl: 3600,
            touched: None,
            rrsets: HashMap::new(),
            listed_at: Instant::now(),
            write_epoch: 0,
        };
        let zones: crate::model::ZoneIndex = [zone].into_iter().collect();
        let built = plan::build(
            &Changes {
                create: vec![endpoint("www.example.com", "A", &["192.0.2.1"])],
                ..Changes::default()
            },
            &zones,
        );

        assert_eq!(describe(&built.zones[0].patches), "www/A");
        assert!(deletions(&built.zones[0]).is_empty());
    }
}
