//! Prometheus metrics, chosen so that each failure this provider exists to prevent is
//! visible rather than inferred.
//!
//! The one to watch is `changes_suppressed_total{reason="identical"}`. On a settled cluster
//! it should climb steadily and `zone_writes_total` should not move at all: that is
//! external-dns asking for writes we are declining to make, which is the whole design. If
//! `zone_writes_total` climbs on an idle cluster instead, the write loop is back.
//!
//! Second is the split between `desec_requests_total{outcome="would_block"}` and
//! `outcome="throttled"`. The first is our own limiter pacing us, which is working as
//! intended. The second is deSEC throttling us, which means either something else shares
//! the account or we restarted and lost the sliding-window state that the limiter keeps
//! only in memory.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

use crate::store::SnapshotStore;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReasonLabel {
    pub reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct KindLabel {
    pub kind: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct EndpointLabel {
    pub endpoint: &'static str,
}

/// What a deSEC call was and how it went.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RequestLabels {
    pub op: &'static str,
    pub outcome: &'static str,
}

// Plain strings rather than an enum: prometheus-client's derive encodes variant names
// verbatim, so `WouldBlock` would reach a dashboard as `WouldBlock`. Metric label values
// are an interface, and spelling them out is the only way to be sure of them.
pub mod op {
    pub const LIST_ZONES: &str = "list_zones";
    pub const LIST_RRSETS: &str = "list_rrsets";
    pub const WRITE: &str = "write";
}

pub mod outcome {
    pub const OK: &str = "ok";
    /// deSEC answered 429: something else shares the account, or we restarted and lost the
    /// limiter state that lives only in memory.
    pub const THROTTLED: &str = "throttled";
    /// Our own limiter declined before making a request. Working as intended.
    pub const WOULD_BLOCK: &str = "would_block";
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const ERROR: &str = "error";
}

/// The record type of an RRset deSEC rewrote on storage.
///
/// An owned `String` rather than the `&'static str` the other label sets use, because
/// `RecordType::Other` carries a mnemonic this build has never heard of. Cardinality is
/// bounded by the number of DNS record types, so it is safe to label on unconditionally.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RecordTypeLabel {
    pub record_type: String,
}

/// A write's fate, per zone.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct WriteLabels {
    /// Empty unless `--metrics-zone-labels` is set. Per-zone visibility is how an operator
    /// sees the 300-writes-a-day cap approaching, but it is cardinality an operator should
    /// opt into.
    pub zone: String,
    /// `ok`, or `cooling_down` for a write we declined to make because deSEC threw a 429 at
    /// this zone recently. Deliberately not `throttled`, which already means deSEC answered
    /// 429, nor `would_block`, which already means our own limiter declined.
    pub result: &'static str,
}

pub struct Metrics {
    registry: Registry,
    zone_labels: bool,

    pub changes_suppressed: Family<ReasonLabel, Counter>,
    pub adjust_mutations: Family<KindLabel, Counter>,
    pub zone_writes: Family<WriteLabels, Counter>,
    pub write_normalized: Family<RecordTypeLabel, Counter>,
    pub desec_requests: Family<RequestLabels, Counter>,
    pub refresh_zone_skipped: Family<ReasonLabel, Counter>,
    pub refresh_failures: Family<KindLabel, Counter>,
    pub zones_disappeared: Counter,
    pub soft_errors: Family<EndpointLabel, Counter>,

    pub rrsets_per_write: Histogram,
    pub apply_duration: Family<ReasonLabel, Histogram>,
    pub records_duration: Histogram,

    snapshot_generation: Gauge,
    snapshot_age: Gauge,
    zones_managed: Gauge,
    ready: Gauge,

    /// Set by the refresh task's liveness guard; read by `/healthz`.
    pub refresh_attempts: AtomicU64,
}

impl Metrics {
    pub fn new(zone_labels: bool, version: &str) -> Self {
        let mut registry = Registry::with_prefix("webhook");

        let changes_suppressed = Family::<ReasonLabel, Counter>::default();
        registry.register(
            "changes_suppressed",
            "Requested changes that became no deSEC request",
            changes_suppressed.clone(),
        );

        let adjust_mutations = Family::<KindLabel, Counter>::default();
        registry.register(
            "adjust_mutations",
            "Normalizations applied at /adjustendpoints",
            adjust_mutations.clone(),
        );

        let zone_writes = Family::<WriteLabels, Counter>::default();
        registry.register(
            "zone_writes",
            "Bulk RRset writes attempted, by zone and result",
            zone_writes.clone(),
        );

        // Expected to stay at zero. Anything else means deSEC stores a value in a form we
        // did not send, so next cycle's comparison differs again and the write repeats. The
        // label says which record type to look at.
        let write_normalized = Family::<RecordTypeLabel, Counter>::default();
        registry.register(
            "write_normalized",
            "RRsets deSEC rewrote on storage, by record type",
            write_normalized.clone(),
        );

        let desec_requests = Family::<RequestLabels, Counter>::default();
        registry.register(
            "desec_requests",
            "Calls to the deSEC API, by operation and outcome",
            desec_requests.clone(),
        );

        let refresh_zone_skipped = Family::<ReasonLabel, Counter>::default();
        registry.register(
            "refresh_zone_skipped",
            "Zones whose refresh result was not published",
            refresh_zone_skipped.clone(),
        );

        let refresh_failures = Family::<KindLabel, Counter>::default();
        registry.register(
            "refresh_failures",
            "Refresh ticks that failed, by kind",
            refresh_failures.clone(),
        );

        let zones_disappeared = Counter::default();
        registry.register(
            "zones_disappeared",
            "Zones dropped because the account no longer holds them",
            zones_disappeared.clone(),
        );

        let soft_errors = Family::<EndpointLabel, Counter>::default();
        registry.register(
            "soft_errors",
            "Responses in 500..=510, which external-dns retries next cycle",
            soft_errors.clone(),
        );

        // A retype must collapse into one write carrying at least two RRsets. A p50 of 1
        // when retypes are happening means the batching broke.
        let rrsets_per_write = Histogram::new([1.0, 2.0, 4.0, 8.0, 16.0, 64.0, 256.0]);
        registry.register(
            "rrsets_per_write",
            "RRsets carried by one bulk write",
            rrsets_per_write.clone(),
        );

        // Bucketed through external-dns's own budget, so a near-miss on the 15s client
        // timeout is visible before it becomes an outage.
        let apply_duration = Family::<ReasonLabel, Histogram>::new_with_constructor(|| {
            Histogram::new([0.005, 0.05, 0.5, 1.0, 2.0, 4.0, 8.0, 9.0, 12.0, 15.0])
        });
        registry.register(
            "apply_duration_seconds",
            "Time to serve POST /records",
            apply_duration.clone(),
        );

        // Sub-millisecond buckets: this endpoint is served from cache, so anything over
        // ~10ms means it touched the network or blocked on a lock.
        let records_duration = Histogram::new([0.0001, 0.001, 0.01, 0.1, 1.0]);
        registry.register(
            "records_duration_seconds",
            "Time to serve GET /records",
            records_duration.clone(),
        );

        let snapshot_generation = Gauge::default();
        registry.register(
            "snapshot_generation",
            "Snapshot generation; a flat value means the refresher stopped",
            snapshot_generation.clone(),
        );

        let snapshot_age = Gauge::default();
        registry.register(
            "snapshot_age_seconds",
            "Seconds since the last fully successful refresh",
            snapshot_age.clone(),
        );

        let zones_managed = Gauge::default();
        registry.register(
            "zones",
            "Zones currently served from the snapshot",
            zones_managed.clone(),
        );

        let ready = Gauge::default();
        registry.register("ready", "Whether /readyz would answer 200", ready.clone());

        let build_info = Family::<KindLabel, Gauge>::default();
        build_info
            .get_or_create(&KindLabel {
                kind: Box::leak(version.to_owned().into_boxed_str()),
            })
            .set(1);
        registry.register("build_info", "Build version", build_info);

        Self {
            registry,
            zone_labels,
            changes_suppressed,
            adjust_mutations,
            zone_writes,
            write_normalized,
            desec_requests,
            refresh_zone_skipped,
            refresh_failures,
            zones_disappeared,
            soft_errors,
            rrsets_per_write,
            apply_duration,
            records_duration,
            snapshot_generation,
            snapshot_age,
            zones_managed,
            ready,
            refresh_attempts: AtomicU64::new(0),
        }
    }

    /// The zone label to use, honouring `--metrics-zone-labels`.
    pub fn zone_label(&self, zone: &str) -> String {
        if self.zone_labels {
            zone.to_owned()
        } else {
            String::new()
        }
    }

    pub fn record_write(&self, zone: &str, result: &'static str, rrsets: usize) {
        self.zone_writes
            .get_or_create(&WriteLabels {
                zone: self.zone_label(zone),
                result,
            })
            .inc();
        if result == "ok" {
            #[allow(clippy::cast_precision_loss)]
            self.rrsets_per_write.observe(rrsets as f64);
        }
    }

    /// Count and describe an RRset deSEC stored in a form other than the one we sent.
    ///
    /// Logged at info rather than warn: nothing is broken at the moment it happens, and one
    /// line per occurrence is affordable precisely because it should not recur. If it does
    /// recur every cycle, that repetition is the finding.
    pub fn record_normalized(&self, normalized: &crate::apply::Normalized) {
        self.write_normalized
            .get_or_create(&RecordTypeLabel {
                record_type: normalized.key.record_type.as_str().to_owned(),
            })
            .inc();
        tracing::info!(
            zone = %normalized.zone,
            subname = %normalized.key.subname.as_payload(),
            record_type = %normalized.key.record_type.as_str(),
            sent = ?normalized.sent.records(),
            sent_ttl = normalized.sent.ttl,
            stored = ?normalized.stored.records(),
            stored_ttl = normalized.stored.ttl,
            "deSEC stored this RRset in a different form than we sent; the next cycle will \
             compare against the stored form and plan the same write again"
        );
    }

    /// Classify a deSEC failure the same way the HTTP layer does, so the two agree.
    pub fn record_desec_error(&self, op: &'static str, error: &desec::Error) {
        let outcome = match error {
            desec::Error::RateLimitWouldBlock { .. } => outcome::WOULD_BLOCK,
            desec::Error::RateLimited { .. } => outcome::THROTTLED,
            _ if error.is_unauthorized() || error.is_forbidden() => outcome::UNAUTHORIZED,
            _ => outcome::ERROR,
        };
        self.desec_requests
            .get_or_create(&RequestLabels { op, outcome })
            .inc();
    }

    pub fn record_desec_ok(&self, op: &'static str) {
        self.desec_requests
            .get_or_create(&RequestLabels {
                op,
                outcome: outcome::OK,
            })
            .inc();
    }

    pub fn record_suppressed(&self, tally: &crate::plan::Tally) {
        for (reason, count) in [
            ("identical", tally.identical),
            ("delete_absent", tally.delete_absent),
            ("no_managed_zone", tally.no_managed_zone),
            ("unusable", tally.unusable),
        ] {
            if count > 0 {
                self.changes_suppressed
                    .get_or_create(&ReasonLabel { reason })
                    .inc_by(count);
            }
        }
    }

    pub fn record_adjustments(&self, tally: &crate::adjust::Tally) {
        for (kind, count) in [
            ("ttl_clamped", tally.ttl_clamped),
            ("name_canonicalized", tally.name_canonicalized),
            ("rdata_canonicalized", tally.rdata_canonicalized),
            ("dropped_no_zone", tally.dropped_no_zone),
            ("dropped_bad_type", tally.dropped_bad_type),
        ] {
            if count > 0 {
                self.adjust_mutations
                    .get_or_create(&KindLabel { kind })
                    .inc_by(count);
            }
        }
    }

    /// Render the registry, refreshing the snapshot-derived gauges first.
    ///
    /// Those are sampled at scrape time rather than pushed from the refresh loop, because
    /// snapshot *age* is exactly the thing that keeps changing while nothing happens — a
    /// pushed value would look healthy precisely when the refresher had stopped.
    pub fn encode(&self, store: &SnapshotStore, ready: bool) -> Result<String, std::fmt::Error> {
        let snapshot = store.load();

        self.snapshot_generation
            .set(i64::try_from(snapshot.generation).unwrap_or(i64::MAX));
        self.zones_managed
            .set(i64::try_from(snapshot.zones.len()).unwrap_or(i64::MAX));
        self.snapshot_age.set(
            snapshot
                .age()
                .and_then(|age| i64::try_from(age.as_secs()).ok())
                .unwrap_or(-1),
        );
        self.ready.set(i64::from(ready));

        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &self.registry)?;
        Ok(out)
    }

    pub fn note_refresh_attempt(&self) {
        self.refresh_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn refresh_attempts(&self) -> u64 {
        self.refresh_attempts.load(Ordering::Relaxed)
    }

    /// A one-line summary for the startup log, so the operator can see the budget the
    /// configuration implies without scraping anything.
    pub fn describe_budget(estimated_daily_reads: u64) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            "about {estimated_daily_reads} read requests per day against deSEC's account-wide \
             limit of 2000"
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> Metrics {
        Metrics::new(false, "0.0.1-test")
    }

    #[tokio::test]
    async fn an_unpopulated_snapshot_reports_a_negative_age() {
        let metrics = metrics();
        let rendered = metrics
            .encode(&SnapshotStore::new(), false)
            .expect("encodes");

        // -1 rather than 0: a fresh snapshot and one that was never loaded must not look
        // alike on a dashboard.
        assert!(
            rendered.contains("webhook_snapshot_age_seconds -1"),
            "{rendered}"
        );
        assert!(rendered.contains("webhook_ready 0"));
    }

    #[tokio::test]
    async fn suppression_reasons_are_counted_separately() {
        let metrics = metrics();
        metrics.record_suppressed(&crate::plan::Tally {
            identical: 3,
            no_managed_zone: 1,
            ..crate::plan::Tally::default()
        });

        let rendered = metrics
            .encode(&SnapshotStore::new(), false)
            .expect("encodes");
        assert!(
            rendered.contains(r#"webhook_changes_suppressed_total{reason="identical"} 3"#),
            "{rendered}"
        );
        assert!(
            rendered.contains(r#"webhook_changes_suppressed_total{reason="no_managed_zone"} 1"#)
        );
        // Zero-valued reasons stay off the wire rather than cluttering it.
        assert!(!rendered.contains(r#"reason="delete_absent""#));
    }

    #[test]
    fn zone_labels_are_omitted_unless_asked_for() {
        assert_eq!(metrics().zone_label("example.com"), "");
        assert_eq!(
            Metrics::new(true, "0.0.1-test").zone_label("example.com"),
            "example.com"
        );
    }

    #[tokio::test]
    async fn a_local_refusal_and_a_server_throttle_are_distinguishable() {
        let metrics = metrics();
        metrics.record_desec_error(
            op::WRITE,
            &desec::Error::RateLimitWouldBlock {
                scope: desec::Scope::DnsApiPerDomainExpensive,
                wait: std::time::Duration::from_secs(1),
                max_wait: std::time::Duration::from_secs(2),
            },
        );

        let rendered = metrics
            .encode(&SnapshotStore::new(), false)
            .expect("encodes");
        // The distinction an operator needs: would_block is our limiter working, throttled
        // means deSEC pushed back and something is unaccounted for.
        assert!(rendered.contains(r#"outcome="would_block""#), "{rendered}");
        assert!(!rendered.contains(r#"outcome="throttled""#));
    }

    /// The label is what tells an operator which record type to look at, so it has to reach
    /// the wire as the mnemonic rather than as anything Rust-shaped.
    #[tokio::test]
    async fn a_rewritten_value_names_its_record_type_on_the_wire() {
        let metrics = metrics();
        metrics.record_normalized(&crate::apply::Normalized {
            zone: "example.com".to_owned(),
            key: crate::model::RrKey::new(
                "v6".parse().expect("valid subname"),
                desec::RecordType::AAAA,
            ),
            sent: crate::model::RrValue::new(["2001:0DB8::0001".to_owned()], 3600),
            stored: crate::model::RrValue::new(["2001:db8::1".to_owned()], 3600),
        });

        let rendered = metrics
            .encode(&SnapshotStore::new(), false)
            .expect("encodes");
        assert!(
            rendered.contains(r#"webhook_write_normalized_total{record_type="AAAA"} 1"#),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn only_successful_writes_are_observed_in_the_rrset_histogram() {
        let metrics = metrics();
        metrics.record_write("example.com", "ok", 2);
        metrics.record_write("example.com", "throttled", 5);

        let rendered = metrics
            .encode(&SnapshotStore::new(), false)
            .expect("encodes");
        assert!(
            rendered.contains("webhook_rrsets_per_write_count 1"),
            "{rendered}"
        );
        assert!(rendered.contains(r#"result="throttled""#));
    }
}
