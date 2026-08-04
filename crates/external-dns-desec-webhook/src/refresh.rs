//! The background loop that keeps the snapshot current.
//!
//! It runs on its own interval, unrelated to external-dns's `--interval`, because the read
//! endpoints are served from cache and so the two have nothing to do with each other. The
//! interval is a budget decision: one zone list per tick, and deSEC allows 2000 requests a
//! day across the whole account. At 60s that poll alone is 1440 of them; at the 180s default
//! it is 480.
//!
//! Within a tick, a zone's records are re-read only when deSEC says the zone changed. That
//! is what `Domain.touched` is for — it is the maximum of the zone's publication time and
//! every RRset's, so one cheap list tells us which of a hundred zones to look at.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use desec::api::domains::Domain;

use crate::metrics::{Metrics, op};
use crate::model::{RrKey, RrValue};
use crate::store::{ListedZone, RefreshUpdate, SnapshotStore};

/// Most zones to re-read in one tick.
///
/// A cap rather than a target. If a hundred zones change at once, spreading them over
/// several ticks keeps one burst from consuming the `dns_api_cheap` per-minute allowance
/// and starving the write path, which shares the account-wide budget.
const MAX_RELISTS_PER_TICK: usize = 10;

/// How much a failing tick backs off, and how far.
const BACKOFF_CAP: Duration = Duration::from_secs(900);

/// Whether the refresh task is still running, and when it last tried.
///
/// Liveness only — deliberately says nothing about whether deSEC is reachable. A throttle
/// window must leave `/healthz` green for its whole duration, because restarting the pod
/// discards the rate limiter's in-memory sliding windows and makes the throttling worse.
#[derive(Clone)]
pub struct Liveness {
    alive: Arc<AtomicBool>,
    last_attempt_unix: Arc<AtomicU64>,
}

impl Default for Liveness {
    fn default() -> Self {
        Self::new()
    }
}

impl Liveness {
    pub fn new() -> Self {
        Self {
            alive: Arc::new(AtomicBool::new(true)),
            last_attempt_unix: Arc::new(AtomicU64::new(now_unix())),
        }
    }

    fn note_attempt(&self) {
        self.last_attempt_unix.store(now_unix(), Ordering::Relaxed);
    }

    /// True when the task is gone, or has not even *tried* in ten intervals.
    ///
    /// Attempts rather than successes: a tick that fails every time is a working loop with
    /// an unreachable API, which is not something restarting fixes.
    pub fn is_wedged(&self, interval: Duration) -> bool {
        if !self.alive.load(Ordering::Relaxed) {
            return true;
        }
        let silence = now_unix().saturating_sub(self.last_attempt_unix.load(Ordering::Relaxed));
        silence > 10 * interval.as_secs().max(1)
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Flips the liveness flag when the task's future is dropped, however it ends — returning,
/// being aborted, or panicking. A bare flag set on the way out of a loop would stay true
/// after a panic, which is the case most worth catching.
struct AliveGuard(Arc<AtomicBool>);

impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

pub struct Refresher {
    client: desec::Client,
    store: SnapshotStore,
    metrics: Arc<Metrics>,
    include: Vec<String>,
    exclude: Vec<String>,
    interval: Duration,
    max_zone_age: Duration,
    liveness: Liveness,
}

impl Refresher {
    pub fn new(
        client: desec::Client,
        store: SnapshotStore,
        metrics: Arc<Metrics>,
        include: Vec<String>,
        exclude: Vec<String>,
        interval: Duration,
        max_zone_age: Duration,
    ) -> Self {
        Self {
            client,
            store,
            metrics,
            include,
            exclude,
            interval,
            max_zone_age,
            liveness: Liveness::new(),
        }
    }

    pub fn liveness(&self) -> Liveness {
        self.liveness.clone()
    }

    /// Refresh until told to stop.
    ///
    /// Never exits on an API error and never calls `exit`. A crash loop would reset the
    /// limiter's in-memory windows on every restart, so the process would keep believing it
    /// had a fresh budget while the server knew otherwise — the fastest possible way to stay
    /// throttled.
    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let _guard = AliveGuard(Arc::clone(&self.liveness.alive));

        // Spread the first tick, so a restart of several replicas does not synchronise them
        // onto the same second.
        let stagger = self
            .interval
            .mul_f64(jitter_fraction(&self.include.join(",")) / 4.0);
        tokio::time::sleep(stagger).await;

        let mut backoff = self.interval;

        loop {
            let update = self.tick().await;
            let failed = !update.zone_list_ok;
            let report = self.store.publish(update).await;

            if report.skipped_raced_write > 0 {
                self.metrics
                    .refresh_zone_skipped
                    .get_or_create(&crate::metrics::ReasonLabel {
                        reason: "raced_write",
                    })
                    .inc_by(report.skipped_raced_write);
            }
            for zone in &report.removed {
                tracing::warn!(zone = %zone, "zone is no longer in the account; dropping it");
                self.metrics.zones_disappeared.inc();
            }

            // A failing tick backs off, but the loop itself never stops: the snapshot stays
            // servable from whatever the last good tick published.
            let wait = if failed {
                backoff = (backoff * 2).min(BACKOFF_CAP);
                backoff
            } else {
                backoff = self.interval;
                self.interval
            };

            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => {
                    tracing::info!("refresh loop stopping");
                    return;
                }
            }
        }
    }

    /// One refresh pass. Separated from the loop so it can be driven directly in tests.
    pub async fn tick(&self) -> RefreshUpdate {
        self.liveness.note_attempt();
        self.metrics.note_refresh_attempt();

        let domains = match self.client.domains().list().all().await {
            Ok(domains) => {
                self.metrics.record_desec_ok(op::LIST_ZONES);
                domains
            }
            Err(error) => {
                self.metrics.record_desec_error(op::LIST_ZONES, &error);
                self.metrics
                    .refresh_failures
                    .get_or_create(&crate::metrics::KindLabel {
                        kind: failure_kind(&error),
                    })
                    .inc();
                tracing::warn!(error = %error, "could not list zones; keeping the current snapshot");
                return RefreshUpdate {
                    zone_list_ok: false,
                    error: Some(error.to_string()),
                    ..RefreshUpdate::default()
                };
            }
        };

        let admitted: Vec<&Domain> = domains
            .iter()
            .filter(|domain| self.admits(&domain.name.to_ascii_lowercase()))
            .collect();

        self.warn_about_delegated_zones_we_exclude(&domains);

        let snapshot = self.store.load();
        let mut update = RefreshUpdate {
            present: admitted
                .iter()
                .map(|domain| domain.name.to_ascii_lowercase())
                .collect(),
            zone_list_ok: true,
            ..RefreshUpdate::default()
        };

        // Zones deSEC says have changed come first; the periodic forced re-read is a
        // backstop and can wait for a later tick when both are due at once.
        let mut changed = Vec::new();
        let mut stale = Vec::new();
        for domain in &admitted {
            let name = domain.name.to_ascii_lowercase();
            match snapshot.zones.get(&name) {
                None => changed.push(*domain),
                Some(zone) if zone.needs_relist(domain.touched) => changed.push(*domain),
                Some(zone) if zone.is_stale(self.stale_after(&name)) => stale.push(*domain),
                Some(_) => {}
            }
        }

        let queued = changed.len() + stale.len();
        let due: Vec<&Domain> = changed
            .into_iter()
            .chain(stale)
            .take(MAX_RELISTS_PER_TICK)
            .collect();

        if queued > due.len() {
            // Never silently. A cap that is being hit every tick means the interval is too
            // long for how much is changing.
            tracing::info!(
                queued,
                listing = due.len(),
                "more zones need re-reading than one tick allows; the rest follow next tick"
            );
        }

        // Sequentially, not concurrently. These share the account-wide budget with the
        // write path, and a burst is what earns a 429 for everyone.
        for domain in due {
            let name = domain.name.to_ascii_lowercase();
            let epoch_at_start = snapshot.zones.get(&name).map_or(0, |zone| zone.write_epoch);

            match self.client.rrsets(&name).list().all().await {
                Ok(rrsets) => {
                    self.metrics.record_desec_ok(op::LIST_RRSETS);
                    tracing::debug!(zone = %name, rrsets = rrsets.len(), "re-read zone");
                    update.listed.push(ListedZone {
                        name,
                        minimum_ttl: domain.minimum_ttl,
                        touched: domain.touched,
                        // Everything deSEC holds, including the records only it may write.
                        // The snapshot is a mirror; hiding those happens at the `/records`
                        // edge. Dropping them here would make a create for one look new
                        // rather than identical, and cost a rejected write every cycle.
                        rrsets: rrsets
                            .iter()
                            .map(|rrset| (RrKey::of(rrset), RrValue::of(rrset)))
                            .collect::<HashMap<_, _>>(),
                        epoch_at_start,
                    });
                }
                Err(error) => {
                    self.metrics.record_desec_error(op::LIST_RRSETS, &error);
                    update.error = Some(error.to_string());

                    if error.is_rate_limited() {
                        // Stop the tick rather than working through the queue collecting
                        // 429s. What has been read is still published; the rest keeps its
                        // previous data and is retried after the backoff.
                        tracing::warn!(
                            zone = %name,
                            "throttled while re-reading zones; publishing what was read"
                        );
                        break;
                    }
                    tracing::warn!(zone = %name, error = %error, "could not re-read zone");
                }
            }
        }

        update
    }

    /// Whether a zone in the account is one we manage.
    ///
    /// Suffix as well as exact, matching external-dns's own filter semantics: `example.com`
    /// admits `example.com` and any zone below it, so a delegated `sub.example.com` is
    /// managed without having to be listed separately.
    fn admits(&self, zone: &str) -> bool {
        let matches = |patterns: &[String]| {
            patterns
                .iter()
                .any(|pattern| zone == pattern || zone.ends_with(&format!(".{pattern}")))
        };
        matches(&self.include) && !matches(&self.exclude)
    }

    /// When this zone's forced re-read falls due.
    ///
    /// Jittered per zone so that a hundred zones listed in the same tick do not all come due
    /// in the same later tick and blow the per-tick cap.
    fn stale_after(&self, zone: &str) -> Duration {
        self.max_zone_age + self.max_zone_age.mul_f64(jitter_fraction(zone) / 2.0)
    }

    /// Warn once per tick about a zone the account holds *below* one we manage but that the
    /// filter excludes.
    ///
    /// This is the early warning for the misconfiguration that produced
    /// `service.sub.sub.dedyn.io`: records for the child end up in the parent, under a
    /// subname that already contains the delegation.
    fn warn_about_delegated_zones_we_exclude(&self, domains: &[Domain]) {
        for domain in domains {
            let name = domain.name.to_ascii_lowercase();
            if self.admits(&name) {
                continue;
            }
            if let Some(parent) = self
                .include
                .iter()
                .find(|parent| name.ends_with(&format!(".{parent}")))
            {
                tracing::warn!(
                    zone = %name,
                    parent = %parent,
                    "the account holds this zone below a managed one, but the filter excludes \
                     it; records for it would be written into the parent zone instead"
                );
            }
        }
    }
}

/// A stable fraction in `[0, 1)` derived from a name, for spreading work.
fn jitter_fraction(seed: &str) -> f64 {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    #[allow(clippy::cast_precision_loss)]
    let scaled = (hasher.finish() % 1000) as f64;
    scaled / 1000.0
}

fn failure_kind(error: &desec::Error) -> &'static str {
    if error.is_rate_limited() {
        "throttled"
    } else if error.is_unauthorized() || error.is_forbidden() {
        "unauthorized"
    } else {
        "error"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(server: &MockServer) -> desec::Client {
        desec::Client::builder()
            .token("i-T3b1h_OI-H9ab8tRS98stGtURe")
            .base_url(format!("{}/api/v1", server.uri()))
            .max_retries(0)
            .max_rate_limit_wait(Duration::from_secs(2))
            .timeout(Duration::from_secs(4))
            .build()
            .expect("builds")
    }

    fn refresher(server: &MockServer, store: SnapshotStore, include: &[&str]) -> Refresher {
        Refresher::new(
            client(server),
            store,
            Arc::new(Metrics::new(false, "test")),
            include.iter().map(|z| (*z).to_owned()).collect(),
            Vec::new(),
            Duration::from_secs(180),
            Duration::from_secs(21_600),
        )
    }

    fn domain_json(name: &str, touched: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "created": "2026-01-01T00:00:00Z",
            "published": touched,
            "touched": touched,
            "minimum_ttl": 3600,
            "keys": [],
        })
    }

    fn rrset_json(domain: &str, subname: &str, record_type: &str) -> serde_json::Value {
        serde_json::json!({
            "domain": domain,
            "subname": subname,
            "type": record_type,
            "name": format!("{subname}.{domain}."),
            "records": ["192.0.2.1"],
            "ttl": 3600,
            "created": "2026-01-01T00:00:00Z",
            "touched": "2026-01-01T00:00:00Z",
        })
    }

    async fn mock_zones(server: &MockServer, domains: Vec<serde_json::Value>) {
        Mock::given(method("GET"))
            .and(path("/api/v1/domains/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(domains))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn a_first_tick_reads_every_managed_zone() {
        let server = MockServer::start().await;
        mock_zones(
            &server,
            vec![
                domain_json("example.com", "2026-01-01T00:00:00Z"),
                // Not admitted by the filter.
                domain_json("other.org", "2026-01-01T00:00:00Z"),
            ],
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/domains/example.com/rrsets/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vec![rrset_json(
                "example.com",
                "www",
                "A",
            )]))
            .expect(1)
            .mount(&server)
            .await;

        let store = SnapshotStore::new();
        let update = refresher(&server, store.clone(), &["example.com"])
            .tick()
            .await;

        assert!(update.zone_list_ok);
        assert_eq!(update.present, vec!["example.com".to_owned()]);
        assert_eq!(update.listed.len(), 1);
        server.verify().await;
    }

    /// The saving that makes a 180s interval affordable: an unchanged zone costs nothing
    /// beyond the one zone list shared by all of them.
    #[tokio::test]
    async fn an_unchanged_zone_is_not_re_read() {
        let server = MockServer::start().await;
        mock_zones(
            &server,
            vec![domain_json("example.com", "2026-01-01T00:00:00Z")],
        )
        .await;
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/domains/.*/rrsets/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
            .expect(1) // the first tick only
            .mount(&server)
            .await;

        let store = SnapshotStore::new();
        let refresher = refresher(&server, store.clone(), &["example.com"]);

        let first = refresher.tick().await;
        store.publish(first).await;
        let second = refresher.tick().await;

        assert!(
            second.listed.is_empty(),
            "touched did not move, so there is nothing to read"
        );
        assert_eq!(second.present, vec!["example.com".to_owned()]);
        server.verify().await;
    }

    #[tokio::test]
    async fn a_zone_whose_touched_moved_is_re_read() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/domains/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(vec![domain_json("example.com", "2026-06-01T00:00:00Z")]),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/domains/.*/rrsets/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
            .mount(&server)
            .await;

        // A snapshot holding an older `touched`.
        let store = SnapshotStore::new();
        store
            .publish(RefreshUpdate {
                present: vec!["example.com".to_owned()],
                listed: vec![ListedZone {
                    name: "example.com".to_owned(),
                    minimum_ttl: 3600,
                    touched: Some(
                        "2026-01-01T00:00:00Z"
                            .parse::<chrono::DateTime<chrono::Utc>>()
                            .expect("valid"),
                    ),
                    rrsets: HashMap::new(),
                    epoch_at_start: 0,
                }],
                zone_list_ok: true,
                error: None,
            })
            .await;

        let update = refresher(&server, store, &["example.com"]).tick().await;
        assert_eq!(update.listed.len(), 1);
    }

    /// A zone we wrote to marks itself `touched: None`, which must re-read even though the
    /// server's own value has not changed since.
    #[tokio::test]
    async fn a_zone_we_just_wrote_re_reads_itself() {
        let server = MockServer::start().await;
        mock_zones(
            &server,
            vec![domain_json("example.com", "2026-01-01T00:00:00Z")],
        )
        .await;
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/domains/.*/rrsets/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
            .mount(&server)
            .await;

        let store = SnapshotStore::new();
        let refresher = refresher(&server, store.clone(), &["example.com"]);
        let first = refresher.tick().await;
        store.publish(first).await;

        // Simulates a confirmed write.
        store.invalidate("example.com").await;

        assert_eq!(refresher.tick().await.listed.len(), 1);
    }

    /// A throttle mid-tick publishes what was read and leaves the rest alone. Freezing the
    /// whole cache because one zone was throttled would be worse, and clearing it would be
    /// catastrophic.
    #[tokio::test]
    async fn a_throttle_while_reading_zones_publishes_partial_progress() {
        let server = MockServer::start().await;
        mock_zones(
            &server,
            vec![
                domain_json("a.example.com", "2026-01-01T00:00:00Z"),
                domain_json("b.example.com", "2026-01-01T00:00:00Z"),
            ],
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/domains/a.example.com/rrsets/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/domains/b.example.com/rrsets/"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "60"))
            .mount(&server)
            .await;

        let update = refresher(&server, SnapshotStore::new(), &["example.com"])
            .tick()
            .await;

        // The zone list itself succeeded, so nothing is removed.
        assert!(update.zone_list_ok);
        assert!(update.error.is_some());
        assert!(
            update.listed.len() <= 1,
            "stopped rather than collecting 429s"
        );
    }

    #[tokio::test]
    async fn a_failed_zone_list_reports_itself_as_such() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/domains/"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let update = refresher(&server, SnapshotStore::new(), &["example.com"])
            .tick()
            .await;

        // The flag store::publish keys "do not remove any zone" off.
        assert!(!update.zone_list_ok);
        assert!(update.present.is_empty());
        assert!(update.error.is_some());
    }

    #[test]
    fn the_filter_admits_a_zone_and_anything_delegated_below_it() {
        let server = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(MockServer::start());
        let refresher = refresher(&server, SnapshotStore::new(), &["example.com"]);

        assert!(refresher.admits("example.com"));
        assert!(refresher.admits("sub.example.com"));
        assert!(!refresher.admits("notexample.com"));
        assert!(!refresher.admits("example.org"));
        assert!(!refresher.admits("com"));
    }

    #[test]
    fn forced_re_reads_are_spread_rather_than_bunched() {
        let server = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(MockServer::start());
        let refresher = refresher(&server, SnapshotStore::new(), &["example.com"]);

        let ages: Vec<Duration> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|zone| refresher.stale_after(zone))
            .collect();

        assert!(
            ages.iter().collect::<std::collections::HashSet<_>>().len() > 1,
            "zones listed together must not all come due together"
        );
        for age in ages {
            assert!(age >= Duration::from_secs(21_600));
            assert!(age <= Duration::from_secs(21_600 * 3 / 2));
        }
    }

    #[test]
    fn liveness_tracks_the_task_not_the_api() {
        let liveness = Liveness::new();
        let interval = Duration::from_secs(180);
        assert!(!liveness.is_wedged(interval));

        // A failing tick still counts as an attempt: an unreachable API is not something a
        // restart fixes, and restarting would discard the limiter's state.
        liveness.note_attempt();
        assert!(!liveness.is_wedged(interval));

        // The task ending, however it ends, is.
        let guard = AliveGuard(Arc::clone(&liveness.alive));
        drop(guard);
        assert!(liveness.is_wedged(interval));
    }
}
