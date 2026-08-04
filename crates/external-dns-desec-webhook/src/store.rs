//! Publishing snapshots, and keeping an optimistic update from being undone by a refresh
//! that started before it.
//!
//! Readers go through [`arc_swap`], so `/records` never blocks and never awaits while
//! holding anything. Producers — the refresh task and each zone write — additionally take
//! a mutex, because swapping an `Arc` gives replacement rather than read-modify-write, and
//! eight concurrent zone writes plus a refresh would otherwise lose each other's updates.
//! The mutex is held for microseconds and never across a request.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use desec::api::rrsets::Rrset;
use tokio::sync::Mutex;

use crate::model::{RrKey, RrValue, Snapshot, Zone, ZoneIndex};

/// A zone whose records were just read from the API.
#[derive(Debug, Clone)]
pub struct ListedZone {
    pub name: String,
    pub minimum_ttl: u32,
    pub touched: Option<DateTime<Utc>>,
    pub rrsets: HashMap<RrKey, RrValue>,
    /// The zone's `write_epoch` as it was *before* the listing began.
    ///
    /// Carried all the way through so the publish can tell whether a write landed while
    /// this data was in flight.
    pub epoch_at_start: u64,
}

/// The result of one refresh tick.
#[derive(Debug, Default)]
pub struct RefreshUpdate {
    /// Zones the account holds that the filter admits, whether or not they were re-listed.
    /// Anything absent from this is gone and gets dropped — but only if `zone_list_ok`.
    pub present: Vec<String>,

    /// Zones whose records were read this tick.
    pub listed: Vec<ListedZone>,

    /// Whether the zone list itself was read successfully.
    ///
    /// When it was not, no zone is removed. A throttled or failed list is not evidence
    /// that a zone has gone away, and acting as if it were would empty the snapshot and
    /// ask external-dns to delete everything.
    pub zone_list_ok: bool,

    pub error: Option<String>,
}

/// What a publish did, for metrics.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PublishReport {
    /// Zones whose freshly-read records were discarded because a write landed first.
    pub skipped_raced_write: u64,
    /// Zones dropped because the account no longer holds them.
    pub removed: Vec<String>,
    pub published_zones: usize,
}

#[derive(Clone)]
pub struct SnapshotStore {
    current: Arc<ArcSwap<Snapshot>>,
    writer: Arc<Mutex<()>>,
}

impl Default for SnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(Snapshot::default())),
            writer: Arc::new(Mutex::new(())),
        }
    }

    /// The current snapshot. Lock-free, and cheap enough to call per request.
    pub fn load(&self) -> Arc<Snapshot> {
        self.current.load_full()
    }

    /// Replace the snapshot with one derived from it, serialized against other producers.
    ///
    /// `build` is pure CPU and must never be held across I/O: the mutex it runs under is
    /// what keeps concurrent writes from clobbering each other.
    async fn update<T>(&self, build: impl FnOnce(&Snapshot) -> (Snapshot, T)) -> T {
        let _guard = self.writer.lock().await;
        let (next, outcome) = build(&self.current.load());
        self.current.store(Arc::new(next));
        outcome
    }

    /// Publish a refresh result.
    ///
    /// A zone is published only once we have actually read its records. A zone the account
    /// holds but that we have never listed is left out entirely rather than published
    /// empty, because an empty zone reported to external-dns under `--policy=sync` reads
    /// as "delete every record here". Until it is listed, names in it resolve to nothing
    /// and are skipped with a warning, which is the safe direction to be wrong in.
    pub async fn publish(&self, update: RefreshUpdate) -> PublishReport {
        self.update(|current| {
            let mut report = PublishReport::default();
            let mut zones = ZoneIndex::default();

            let listed: HashMap<&str, &ListedZone> = update
                .listed
                .iter()
                .map(|zone| (zone.name.as_str(), zone))
                .collect();

            for name in &update.present {
                let existing = current.zones.get(name);

                match listed.get(name.as_str()) {
                    Some(fresh) => {
                        let raced =
                            existing.is_some_and(|zone| zone.write_epoch != fresh.epoch_at_start);

                        if raced {
                            // The listing predates a write that has since landed, so it
                            // holds pre-write records. Publishing them would undo the
                            // write in the cache and make external-dns plan it again.
                            // Keep the written state; its `touched: None` re-lists it next
                            // tick anyway.
                            report.skipped_raced_write += 1;
                            if let Some(zone) = existing {
                                zones.insert(zone.as_ref().clone());
                            }
                        } else {
                            zones.insert(Zone {
                                name: fresh.name.clone(),
                                minimum_ttl: fresh.minimum_ttl,
                                touched: fresh.touched,
                                rrsets: fresh.rrsets.clone(),
                                listed_at: Instant::now(),
                                write_epoch: existing.map_or(0, |zone| zone.write_epoch),
                            });
                        }
                    }
                    // Not re-listed this tick: carry it over unchanged if we have it, and
                    // leave it out if we have never read it.
                    None => {
                        if let Some(zone) = existing {
                            zones.insert(zone.as_ref().clone());
                        }
                    }
                }
            }

            // Only a successful list is evidence that a zone is gone.
            if update.zone_list_ok {
                for name in current.zones.names() {
                    if !update.present.iter().any(|present| present == name) {
                        report.removed.push(name.clone());
                    }
                }
            } else {
                for zone in current.zones.zones() {
                    if zones.get(&zone.name).is_none() {
                        zones.insert(zone.as_ref().clone());
                    }
                }
            }

            report.published_zones = zones.len();

            let next = Snapshot {
                zones,
                generation: current.generation.wrapping_add(1),
                // Only a full, successful list makes the snapshot servable. A partial
                // publish keeps whatever the last good one established.
                last_full_ok: if update.zone_list_ok {
                    Some(Instant::now())
                } else {
                    current.last_full_ok
                },
                last_error: update.error.as_deref().map(Arc::from),
            };

            (next, report)
        })
        .await
    }

    /// Fold a confirmed write into the snapshot.
    ///
    /// `confirmed` is what deSEC returned, not what we sent. Using the response means we
    /// never have to predict how the server normalized a value — how it split a long TXT
    /// record, or whether it clamped a TTL — and so the cached value cannot disagree with
    /// the stored one.
    ///
    /// The zone is then marked `touched: None`, which forces a re-list on the next tick.
    /// deSEC's own `touched` from the response is deliberately *not* stored: doing so would
    /// suppress that re-list and let any divergence persist unnoticed.
    pub async fn apply_confirmed(&self, zone: &str, confirmed: &[Rrset], deleted: &[RrKey]) {
        self.update(|current| {
            let mut next = current.successor();

            if let Some(existing) = current.zones.get(zone) {
                let mut updated = existing.as_ref().clone();

                for key in deleted {
                    updated.rrsets.remove(key);
                }
                for rrset in confirmed {
                    let key = RrKey::of(rrset);
                    // deSEC may echo a deletion as `records: []` or omit it from the
                    // response; both spellings have to mean the same thing here.
                    if rrset.records.is_empty() {
                        updated.rrsets.remove(&key);
                    } else {
                        updated.rrsets.insert(key, RrValue::of(rrset));
                    }
                }

                updated.write_epoch = updated.write_epoch.wrapping_add(1);
                updated.touched = None;
                next.zones.insert(updated);
            }

            (next, ())
        })
        .await;
    }

    /// Mark a zone as untrusted, so the next tick re-reads it.
    ///
    /// Called for every zone a write touched but did not confirm — failed, throttled, or
    /// cancelled by our own deadline. The invariant is that a zone we *attempted* to write
    /// is never left claiming to know its own contents.
    pub async fn invalidate(&self, zone: &str) {
        self.update(|current| {
            let mut next = current.successor();
            if let Some(existing) = current.zones.get(zone) {
                let mut updated = existing.as_ref().clone();
                updated.touched = None;
                next.zones.insert(updated);
            }
            (next, ())
        })
        .await;
    }

    /// Drop a zone the account no longer holds.
    ///
    /// Continuing to serve it would wedge the cycle: external-dns keeps planning changes
    /// for records in it, and every write 404s.
    pub async fn forget(&self, zone: &str) {
        self.update(|current| {
            let mut next = current.successor();
            next.zones.remove(zone);
            (next, ())
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use desec::{RecordType, Subname};

    fn rrset(subname: &str, record_type: &str, ttl: u32, records: &[&str]) -> Rrset {
        serde_json::from_value(serde_json::json!({
            "domain": "example.com",
            "subname": subname,
            "type": record_type,
            "name": "ignored.",
            "records": records,
            "ttl": ttl,
            "created": "2026-01-01T00:00:00Z",
            "touched": "2026-01-01T00:00:00Z",
        }))
        .expect("valid rrset")
    }

    fn key(subname: &str, record_type: RecordType) -> RrKey {
        RrKey::new(Subname::new(subname).expect("valid"), record_type)
    }

    fn touched(when: &str) -> Option<DateTime<Utc>> {
        Some(
            DateTime::parse_from_rfc3339(when)
                .expect("valid")
                .with_timezone(&Utc),
        )
    }

    fn listed(
        name: &str,
        epoch_at_start: u64,
        rrsets: &[(&str, RecordType, u32, &[&str])],
    ) -> ListedZone {
        ListedZone {
            name: name.to_owned(),
            minimum_ttl: 3600,
            touched: touched("2026-01-01T00:00:00Z"),
            rrsets: rrsets
                .iter()
                .map(|(subname, record_type, ttl, records)| {
                    (
                        key(subname, record_type.clone()),
                        RrValue::new(records.iter().map(|r| (*r).to_owned()), *ttl),
                    )
                })
                .collect(),
            epoch_at_start,
        }
    }

    fn full(listed_zones: Vec<ListedZone>) -> RefreshUpdate {
        RefreshUpdate {
            present: listed_zones.iter().map(|zone| zone.name.clone()).collect(),
            listed: listed_zones,
            zone_list_ok: true,
            error: None,
        }
    }

    #[tokio::test]
    async fn a_fresh_listing_becomes_the_snapshot() {
        let store = SnapshotStore::new();
        assert!(!store.load().is_populated());

        store
            .publish(full(vec![listed(
                "example.com",
                0,
                &[("www", RecordType::A, 3600, &["192.0.2.1"])],
            )]))
            .await;

        let snapshot = store.load();
        assert!(snapshot.is_populated());
        assert_eq!(snapshot.zones.len(), 1);
        assert_eq!(
            snapshot
                .zones
                .get("example.com")
                .expect("published")
                .rrsets
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_zone_the_account_holds_but_we_have_not_listed_is_not_published_empty() {
        let store = SnapshotStore::new();

        store
            .publish(RefreshUpdate {
                present: vec![
                    "listed.example.com".to_owned(),
                    "new.example.com".to_owned(),
                ],
                listed: vec![listed("listed.example.com", 0, &[])],
                zone_list_ok: true,
                error: None,
            })
            .await;

        let snapshot = store.load();
        // Publishing new.example.com as empty would read as "delete everything in it".
        assert!(snapshot.zones.get("new.example.com").is_none());
        assert!(snapshot.zones.get("listed.example.com").is_some());
    }

    #[tokio::test]
    async fn a_confirmed_write_lands_in_the_snapshot_and_forces_a_relist() {
        let store = SnapshotStore::new();
        store
            .publish(full(vec![listed(
                "example.com",
                0,
                &[("old", RecordType::A, 3600, &["192.0.2.1"])],
            )]))
            .await;

        store
            .apply_confirmed(
                "example.com",
                &[rrset("new", "A", 3600, &["192.0.2.9"])],
                &[key("old", RecordType::A)],
            )
            .await;

        let snapshot = store.load();
        let zone = snapshot.zones.get("example.com").expect("present");
        assert!(!zone.rrsets.contains_key(&key("old", RecordType::A)));
        assert_eq!(
            zone.rrsets
                .get(&key("new", RecordType::A))
                .map(RrValue::records),
            Some(["192.0.2.9".to_owned()].as_slice())
        );
        assert_eq!(zone.write_epoch, 1);
        // Self-invalidated: optimism is reconciled against reality next tick.
        assert!(zone.touched.is_none());
    }

    #[tokio::test]
    async fn a_deletion_echoed_as_an_empty_record_list_is_still_a_deletion() {
        let store = SnapshotStore::new();
        store
            .publish(full(vec![listed(
                "example.com",
                0,
                &[("gone", RecordType::A, 3600, &["192.0.2.1"])],
            )]))
            .await;

        // deSEC may echo the deletion rather than omitting it. Both must mean the same.
        store
            .apply_confirmed("example.com", &[rrset("gone", "A", 3600, &[])], &[])
            .await;

        assert!(
            store
                .load()
                .zones
                .get("example.com")
                .expect("present")
                .rrsets
                .is_empty()
        );
    }

    /// The race the epoch exists for: a refresh reads the zone, a write lands, then the
    /// refresh publishes. Its records are pre-write, so publishing them would undo the
    /// write in the cache and external-dns would plan it all over again.
    #[tokio::test]
    async fn a_listing_that_lost_a_race_with_a_write_is_discarded() {
        let store = SnapshotStore::new();
        store
            .publish(full(vec![listed(
                "example.com",
                0,
                &[("www", RecordType::A, 3600, &["192.0.2.1"])],
            )]))
            .await;

        // A refresh samples the epoch here...
        let epoch_at_start = store
            .load()
            .zones
            .get("example.com")
            .expect("present")
            .write_epoch;

        // ...a write lands while it is listing...
        store
            .apply_confirmed(
                "example.com",
                &[rrset("www", "A", 3600, &["192.0.2.99"])],
                &[],
            )
            .await;

        // ...and it publishes the pre-write records it read.
        let report = store
            .publish(full(vec![listed(
                "example.com",
                epoch_at_start,
                &[("www", RecordType::A, 3600, &["192.0.2.1"])],
            )]))
            .await;

        assert_eq!(report.skipped_raced_write, 1);
        assert_eq!(
            store
                .load()
                .zones
                .get("example.com")
                .expect("present")
                .rrsets
                .get(&key("www", RecordType::A))
                .map(RrValue::records),
            Some(["192.0.2.99".to_owned()].as_slice()),
            "the write must survive the refresh that raced it"
        );
    }

    /// The other order: the refresh samples the epoch after the write, so its data is
    /// current and must win.
    #[tokio::test]
    async fn a_listing_taken_after_a_write_replaces_the_optimistic_value() {
        let store = SnapshotStore::new();
        store
            .publish(full(vec![listed(
                "example.com",
                0,
                &[("www", RecordType::A, 3600, &["192.0.2.1"])],
            )]))
            .await;
        store
            .apply_confirmed(
                "example.com",
                &[rrset("www", "A", 3600, &["192.0.2.99"])],
                &[],
            )
            .await;

        let epoch_at_start = store
            .load()
            .zones
            .get("example.com")
            .expect("present")
            .write_epoch;

        let report = store
            .publish(full(vec![listed(
                "example.com",
                epoch_at_start,
                &[("www", RecordType::A, 7200, &["192.0.2.99"])],
            )]))
            .await;

        assert_eq!(report.skipped_raced_write, 0);
        let zone = store.load();
        let zone = zone.zones.get("example.com").expect("present");
        assert_eq!(
            zone.rrsets.get(&key("www", RecordType::A)).map(|v| v.ttl),
            Some(7200)
        );
        // The server's own touched is restored, so the forced re-list stops.
        assert!(zone.touched.is_some());
    }

    #[tokio::test]
    async fn invalidating_leaves_the_records_but_forces_a_relist() {
        let store = SnapshotStore::new();
        store
            .publish(full(vec![listed(
                "example.com",
                0,
                &[("www", RecordType::A, 3600, &["192.0.2.1"])],
            )]))
            .await;

        store.invalidate("example.com").await;

        let snapshot = store.load();
        let zone = snapshot.zones.get("example.com").expect("still served");
        assert!(zone.touched.is_none());
        assert_eq!(zone.rrsets.len(), 1, "stale records still beat none");
    }

    #[tokio::test]
    async fn a_zone_missing_from_the_account_is_dropped() {
        let store = SnapshotStore::new();
        store
            .publish(full(vec![
                listed("a.example.com", 0, &[]),
                listed("b.example.com", 0, &[]),
            ]))
            .await;

        let report = store
            .publish(full(vec![listed("a.example.com", 0, &[])]))
            .await;

        assert_eq!(report.removed, vec!["b.example.com".to_owned()]);
        assert!(store.load().zones.get("b.example.com").is_none());
    }

    /// A throttled or failed zone list is not evidence that a zone has gone away. Treating
    /// it as such would empty the snapshot, and an empty snapshot under --policy=sync is a
    /// request to delete everything.
    #[tokio::test]
    async fn a_failed_zone_list_removes_nothing_and_keeps_the_snapshot_servable() {
        let store = SnapshotStore::new();
        store
            .publish(full(vec![
                listed("a.example.com", 0, &[]),
                listed("b.example.com", 0, &[]),
            ]))
            .await;
        let established = store.load().last_full_ok;

        let report = store
            .publish(RefreshUpdate {
                present: Vec::new(),
                listed: Vec::new(),
                zone_list_ok: false,
                error: Some("429 Too Many Requests".to_owned()),
            })
            .await;

        assert!(report.removed.is_empty());
        let snapshot = store.load();
        assert_eq!(snapshot.zones.len(), 2, "both zones still served");
        assert!(snapshot.is_populated());
        assert_eq!(
            snapshot.last_full_ok, established,
            "age is not reset by a failure"
        );
        assert!(snapshot.last_error.is_some());
    }

    #[tokio::test]
    async fn every_publish_advances_the_generation() {
        let store = SnapshotStore::new();
        let before = store.load().generation;

        store
            .publish(full(vec![listed("example.com", 0, &[])]))
            .await;
        store.invalidate("example.com").await;
        store.forget("example.com").await;

        assert_eq!(store.load().generation, before + 3);
        assert!(store.load().zones.is_empty());
    }
}
