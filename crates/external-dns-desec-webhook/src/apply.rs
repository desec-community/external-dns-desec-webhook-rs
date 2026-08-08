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

use std::sync::{Arc, Mutex};
use std::time::Duration;

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

#[derive(Debug, Default)]
pub struct ApplyReport {
    /// Changes that became no requests, by reason.
    pub suppressed: plan::Tally,
    /// Zone name and how many RRsets its one request carried.
    pub written: Vec<(String, usize)>,
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
    /// Serializes applies against each other.
    ///
    /// external-dns should not overlap two reconciles, but if it does, two handlers
    /// diffing against the same snapshot would each plan the same write.
    gate: Arc<tokio::sync::Mutex<()>>,
}

impl Applier {
    pub fn new(client: desec::Client, store: SnapshotStore, dry_run: bool) -> Self {
        Self {
            client,
            store,
            dry_run,
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

        let attempted: Vec<String> = plan.zones.iter().map(|zone| zone.zone.clone()).collect();
        let results = Arc::new(Mutex::new(Vec::new()));

        let timed_out = tokio::time::timeout(DEADLINE, self.write_all(plan.zones, &results))
            .await
            .is_err();

        let mut report = ApplyReport {
            suppressed: plan.tally,
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
            let permits = Arc::clone(&permits);
            let results = Arc::clone(results);

            tasks.spawn(async move {
                let Ok(_permit) = permits.acquire().await else {
                    return;
                };
                let outcome = write_zone(&client, &store, &zone).await;
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
async fn write_zone(
    client: &desec::Client,
    store: &SnapshotStore,
    plan: &ZonePlan,
) -> Result<usize, WebhookError> {
    let rrsets = plan.patches.len();
    tracing::debug!(zone = %plan.zone, rrsets, "writing");

    match client.rrsets(&plan.zone).patch_bulk(&plan.patches).await {
        Ok(confirmed) => {
            store
                .apply_confirmed(&plan.zone, &confirmed, &plan.deleted)
                .await;
            Ok(rrsets)
        }
        Err(error) => {
            let reported = classify(&error);

            if error.is_not_found() {
                // The zone is gone from the account. Keeping it would wedge the cycle:
                // external-dns goes on planning changes for it, and every write 404s.
                tracing::warn!(zone = %plan.zone, "zone no longer exists; dropping it");
                store.forget(&plan.zone).await;
            } else {
                store.invalidate(&plan.zone).await;
            }

            tracing::warn!(
                zone = %plan.zone,
                rrsets,
                error = %error,
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
        let applier = Applier::new(client(&server), store, false);

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
        let applier = Applier::new(client(&server), store, false);

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
            let applier = Applier::new(client(&server), store, false);

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
        let applier = Applier::new(client(&server), store.clone(), false);

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
        let applier = Applier::new(client(&server), store.clone(), false);

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
        let applier = Applier::new(client(&server), store.clone(), false);

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
        let applier = Applier::new(client(&server), store, true);

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
        let applier = Applier::new(client(&server), store, false);

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

        let applier = Applier::new(client(&server), store, false);
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

        let applier = Applier::new(client(&server), store, false);
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
