//! The cached view of deSEC that the read endpoints are served from.
//!
//! `/records` and `/adjustendpoints` answer from a [`Snapshot`] and never call the API,
//! which is what makes them fast enough to be safe: external-dns allows 15 seconds for a
//! whole round trip and does not retry within a cycle, so a handler that waits on a
//! throttled API is a handler that takes external-dns down.
//!
//! Nothing here is async, and nothing here performs I/O.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use desec::api::domains::Domain;
use desec::api::rrsets::Rrset;
use desec::{RecordType, Subname};

/// What identifies an RRset within a zone. deSEC's own primary key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RrKey {
    pub subname: Subname,
    pub record_type: RecordType,
}

impl RrKey {
    pub fn new(subname: Subname, record_type: RecordType) -> Self {
        Self {
            subname,
            record_type,
        }
    }

    pub fn of(rrset: &Rrset) -> Self {
        Self::new(rrset.subname.clone(), rrset.record_type.clone())
    }
}

/// What an RRset holds, in deSEC's own representation.
///
/// Records are sorted and deduplicated by the only constructor, which is what makes `==`
/// a valid "would this write change anything?" test. deSEC does not promise an order, and
/// external-dns does not either, so comparing unsorted lists would report a change every
/// time the two happened to disagree — and a reported change is a write against a budget
/// of 300 per day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrValue {
    records: Vec<String>,
    pub ttl: u32,
}

impl RrValue {
    pub fn new(records: impl IntoIterator<Item = String>, ttl: u32) -> Self {
        let mut records: Vec<String> = records.into_iter().collect();
        records.sort();
        records.dedup();
        Self { records, ttl }
    }

    pub fn of(rrset: &Rrset) -> Self {
        Self::new(rrset.records.iter().cloned(), rrset.ttl)
    }

    pub fn records(&self) -> &[String] {
        &self.records
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// One deSEC zone and everything we know about it.
#[derive(Debug, Clone)]
pub struct Zone {
    /// Lowercase, no trailing dot. Also the key deSEC's per-domain write throttle uses,
    /// so it has to match what we pass to the API exactly.
    pub name: String,

    /// The zone's own TTL floor. Read from the API rather than assumed to be 3600:
    /// clamping to a wrong value is the same bug as not clamping at all, because
    /// external-dns compares what we report against what the source asked for.
    pub minimum_ttl: u32,

    /// deSEC's `touched`, the maximum of the zone's publication time and every RRset's.
    ///
    /// `None` means "we do not trust what we hold" and forces a re-list. That is how a
    /// zone we have just written invalidates itself.
    pub touched: Option<DateTime<Utc>>,

    /// deSEC's wire representation: TXT still quoted, RDATA names still qualified.
    /// Translation happens at the edge, so what is cached is what the API would return.
    pub rrsets: HashMap<RrKey, RrValue>,

    pub listed_at: Instant,

    /// Incremented on every confirmed write.
    ///
    /// A refresh that began before a write and finished after it holds pre-write records;
    /// publishing them would undo the write in the cache and make external-dns plan it
    /// again. Comparing the epoch it sampled at the start against the current one is how
    /// the refresher notices it lost that race.
    pub write_epoch: u64,
}

impl Zone {
    /// A zone we know exists but have not listed yet.
    ///
    /// `touched: None` so the first refresh always lists it. It is deliberately not
    /// published to a snapshot in this state: an empty zone reported to external-dns
    /// under `--policy=sync` reads as "delete everything here".
    pub fn unlisted(domain: &Domain) -> Self {
        Self {
            name: domain.name.to_ascii_lowercase(),
            minimum_ttl: domain.minimum_ttl,
            touched: None,
            rrsets: HashMap::new(),
            listed_at: Instant::now(),
            write_epoch: 0,
        }
    }

    /// Whether the zone's records must be fetched again.
    ///
    /// Compares two server-supplied values and nothing else. It never looks at the local
    /// clock, so clock skew between us and deSEC cannot make a fresh cache look stale or
    /// a stale one look fresh.
    ///
    /// Inequality rather than "is newer": a server clock adjustment or a restore from
    /// backup can move `touched` backwards, and backwards still means what we hold is not
    /// what the zone contains.
    pub fn needs_relist(&self, fresh: Option<DateTime<Utc>>) -> bool {
        self.touched != fresh
    }

    /// Whether the periodic forced re-list is due.
    ///
    /// A backstop against a bug in our own change detection rather than against the API.
    /// If `touched` ever stops telling us the truth, this bounds how long we can be wrong.
    pub fn is_stale(&self, max_age: Duration) -> bool {
        self.listed_at.elapsed() >= max_age
    }
}

/// The managed zones, indexed for zone-cut resolution.
#[derive(Debug, Default, Clone)]
pub struct ZoneIndex {
    by_name: HashMap<String, Arc<Zone>>,
}

impl ZoneIndex {
    /// The zone a fully-qualified name belongs in: the longest managed suffix of it.
    ///
    /// Longest, not first: with both `dedyn.io` and `sub.dedyn.io` managed,
    /// `service.sub.dedyn.io` belongs to `sub.dedyn.io`. Getting this wrong is what
    /// produced `service.sub.sub.dedyn.io` in the provider this replaces — the record was
    /// created in the apex zone under a subname that already contained the delegation.
    ///
    /// `qname` must already be canonical (lowercase, no trailing dot); walking labels is
    /// O(labels) hash probes and allocates nothing.
    pub fn zone_for(&self, qname: &str) -> Option<&Arc<Zone>> {
        let mut cursor = qname;
        loop {
            // The full name first, so an apex endpoint resolves to its own zone.
            if let Some(zone) = self.by_name.get(cursor) {
                return Some(zone);
            }
            match cursor.split_once('.') {
                Some((_, rest)) if !rest.is_empty() => cursor = rest,
                _ => return None,
            }
        }
    }

    pub fn get(&self, name: &str) -> Option<&Arc<Zone>> {
        self.by_name.get(name)
    }

    pub fn insert(&mut self, zone: Zone) {
        self.by_name.insert(zone.name.clone(), Arc::new(zone));
    }

    pub fn remove(&mut self, name: &str) -> Option<Arc<Zone>> {
        self.by_name.remove(name)
    }

    pub fn zones(&self) -> impl Iterator<Item = &Arc<Zone>> {
        self.by_name.values()
    }

    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.by_name.keys()
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

impl FromIterator<Zone> for ZoneIndex {
    fn from_iter<I: IntoIterator<Item = Zone>>(zones: I) -> Self {
        let mut index = Self::default();
        for zone in zones {
            index.insert(zone);
        }
        index
    }
}

/// An immutable view of every managed zone, published wholesale.
#[derive(Debug, Default)]
pub struct Snapshot {
    pub zones: ZoneIndex,

    /// Increments on every publish. A gauge that stops moving means the refresher died,
    /// which is a different failure from a refresher that keeps failing.
    pub generation: u64,

    /// When the zone list was last read in full without error. `None` means we have never
    /// managed it, which is why `/records` answers 503 rather than an empty array.
    pub last_full_ok: Option<Instant>,

    /// The most recent refresh failure, for `/readyz` to report. Kept alongside the data
    /// rather than replacing it: stale records are more useful than none.
    pub last_error: Option<Arc<str>>,
}

impl Snapshot {
    /// Whether the snapshot can be served at all.
    ///
    /// Distinct from freshness. An old snapshot is fine; one that was never populated is
    /// not, because reporting no records to external-dns under `--policy=sync` asks it to
    /// delete every record it owns.
    pub fn is_populated(&self) -> bool {
        self.last_full_ok.is_some()
    }

    pub fn age(&self) -> Option<Duration> {
        self.last_full_ok.map(|at| at.elapsed())
    }

    /// A successor sharing this snapshot's zones, for a publish that changes only some of
    /// them. `Arc<Zone>` values mean this clones one pointer per zone.
    pub fn successor(&self) -> Self {
        Self {
            zones: self.zones.clone(),
            generation: self.generation.wrapping_add(1),
            last_full_ok: self.last_full_ok,
            last_error: self.last_error.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(name: &str) -> Zone {
        Zone {
            name: name.to_owned(),
            minimum_ttl: 3600,
            touched: None,
            rrsets: HashMap::new(),
            listed_at: Instant::now(),
            write_epoch: 0,
        }
    }

    fn index(names: &[&str]) -> ZoneIndex {
        names.iter().map(|name| zone(name)).collect()
    }

    #[test]
    fn a_name_resolves_to_the_longest_managed_suffix() {
        let index = index(&["dedyn.io", "sub.dedyn.io"]);

        for (qname, expected) in [
            ("service.sub.dedyn.io", Some("sub.dedyn.io")),
            ("sub.dedyn.io", Some("sub.dedyn.io")),
            ("other.dedyn.io", Some("dedyn.io")),
            ("dedyn.io", Some("dedyn.io")),
            ("deep.a.b.sub.dedyn.io", Some("sub.dedyn.io")),
        ] {
            assert_eq!(
                index.zone_for(qname).map(|zone| zone.name.as_str()),
                expected,
                "{qname}"
            );
        }
    }

    #[test]
    fn a_name_outside_every_managed_zone_resolves_to_nothing() {
        let index = index(&["example.com"]);

        for qname in [
            // A suffix without a label boundary is not a subdomain.
            "notexample.com",
            // The shape the default --txt-prefix gives an apex endpoint: a sibling of the
            // zone under .com, which no deSEC account of ours can hold.
            "externaldns-a-example.com",
            "com",
            "example.org",
            "",
        ] {
            assert!(index.zone_for(qname).is_none(), "{qname:?}");
        }
    }

    #[test]
    fn a_parent_zone_does_not_capture_a_delegated_child_it_does_not_manage() {
        // Only the child is managed, so the parent's names are not ours.
        let index = index(&["sub.dedyn.io"]);
        assert!(index.zone_for("other.dedyn.io").is_none());
        assert_eq!(
            index.zone_for("a.sub.dedyn.io").map(|z| z.name.as_str()),
            Some("sub.dedyn.io")
        );
    }

    #[test]
    fn record_values_compare_equal_regardless_of_order_or_duplication() {
        let one = RrValue::new(["b".to_owned(), "a".to_owned()], 3600);
        let other = RrValue::new(["a".to_owned(), "b".to_owned(), "a".to_owned()], 3600);
        assert_eq!(one, other);

        // A differing TTL is still a change.
        assert_ne!(one, RrValue::new(["a".to_owned(), "b".to_owned()], 7200));
    }

    #[test]
    fn relisting_is_driven_by_inequality_not_by_recency() {
        let past = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid")
            .with_timezone(&Utc);
        let future = DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .expect("valid")
            .with_timezone(&Utc);

        let mut zone = zone("example.com");
        zone.touched = Some(future);

        assert!(!zone.needs_relist(Some(future)), "unchanged");
        assert!(
            zone.needs_relist(Some(past)),
            "moved backwards: still wrong"
        );
        assert!(zone.needs_relist(None), "vanished: still wrong");
    }

    #[test]
    fn a_never_published_zone_does_not_need_relisting_forever() {
        // touched is None on both sides, so there is nothing to fetch. A zone we have
        // written, by contrast, has None locally and Some remotely, and does re-list.
        let zone = zone("example.com");
        assert!(!zone.needs_relist(None));

        let touched = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid")
            .with_timezone(&Utc);
        assert!(zone.needs_relist(Some(touched)));
    }

    #[test]
    fn an_unpopulated_snapshot_is_not_servable() {
        let empty = Snapshot::default();
        assert!(!empty.is_populated());
        assert!(empty.age().is_none());

        let populated = Snapshot {
            last_full_ok: Some(Instant::now()),
            ..Snapshot::default()
        };
        assert!(populated.is_populated());
    }

    #[test]
    fn a_successor_advances_the_generation_and_keeps_the_zones() {
        let snapshot = Snapshot {
            zones: index(&["example.com"]),
            generation: 7,
            last_full_ok: Some(Instant::now()),
            last_error: None,
        };

        let next = snapshot.successor();
        assert_eq!(next.generation, 8);
        assert_eq!(next.zones.len(), 1);
    }
}
