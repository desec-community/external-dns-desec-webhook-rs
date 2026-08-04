//! Turning external-dns's requested changes into deSEC writes — as few as possible.
//!
//! Two jobs, and the second is the one that keeps the provider inside its budget.
//!
//! **One atomic request per zone.** A record-type change reaches us as `Delete(old A)` and
//! `Create(new CNAME)` for the same name. Sent as separate requests in either order, one
//! of them is invalid — deSEC will not let a CNAME coexist with another type at a subname
//! — so the create is rejected, the delete never runs, and under `--policy=sync` the zone
//! is wedged permanently. Sent as a single bulk `PATCH`, deSEC validates the *resulting*
//! state and accepts it.
//!
//! **No request at all when nothing would change.** external-dns plans updates for reasons
//! of its own: the TXT registry sets `txt/force-update` whenever an ownership record it
//! expects is missing, and `plan.providerSpecificChanged()` promotes that to an `Update`.
//! Comparing each desired RRset against what we hold and dropping the ones that match is
//! what makes a misconfigured cluster merely noisy instead of expensive.

use std::collections::HashMap;

use desec::api::rrsets::BulkPatch;
use desec::{RecordType, Subname};

use crate::adjust::clamp_ttl;
use crate::convert::{canonical_name, record_type_of, records_for, subname_within};
use crate::model::{RrKey, RrValue, Zone, ZoneIndex};
use crate::wire::{Changes, Endpoint};

/// Why a requested change did not become a write.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    /// The desired RRset already holds exactly this. The number that matters: on an idle
    /// cluster this climbing means external-dns is still asking, and we are still not
    /// spending quota on it.
    pub identical: u64,
    /// A delete for an RRset that is not there.
    pub delete_absent: u64,
    /// No managed zone contains the name. Where the apex ownership-record artefact lands.
    pub no_managed_zone: u64,
    /// deSEC would not accept the record type, or the name is not a valid subname.
    pub unusable: u64,
}

impl Tally {
    pub fn suppressed(&self) -> u64 {
        self.identical + self.delete_absent + self.no_managed_zone + self.unusable
    }
}

/// Everything to be written to one zone, in one atomic request.
#[derive(Debug, Clone)]
pub struct ZonePlan {
    pub zone: String,
    /// A single bulk `PATCH` body. Creates, updates and deletes together, because deSEC
    /// validates the resulting zone state rather than each item.
    pub patches: Vec<BulkPatch>,
    /// The RRsets this request removes.
    ///
    /// Tracked separately because deSEC may echo a deletion as `records: []` or omit it
    /// from the response entirely, and the snapshot update has to work either way.
    pub deleted: Vec<RrKey>,
}

#[derive(Debug, Default)]
pub struct Plan {
    pub zones: Vec<ZonePlan>,
    pub tally: Tally,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// How many RRsets the whole plan touches. Recorded per request so that a retype
    /// collapsing into one request with two RRsets is visible as such.
    pub fn rrset_count(&self) -> usize {
        self.zones.iter().map(|zone| zone.patches.len()).sum()
    }
}

/// The RRset an endpoint maps to, once its name has been resolved to a zone.
struct Resolved {
    zone: String,
    key: RrKey,
    ttl: u32,
    records: Vec<String>,
}

/// Group requested changes into one atomic write per zone, dropping everything that would
/// not change stored state.
pub fn build(changes: &Changes, zones: &ZoneIndex) -> Plan {
    let mut tally = Tally::default();

    // Creates and updates are the same thing to a bulk PATCH: it upserts. `updateOld` is
    // only external-dns telling us what it thought was there, which we do not need — we
    // have the snapshot.
    let mut desired: HashMap<(String, RrKey), Resolved> = HashMap::new();
    for endpoint in changes.create.iter().chain(&changes.update_new) {
        let Some(resolved) = resolve(endpoint, zones, &mut tally) else {
            continue;
        };

        // deSEC has one RRset per (subname, type); external-dns can send several
        // endpoints for one name distinguished only by `setIdentifier`, which deSEC has no
        // equivalent of. Merging their records is the closest faithful mapping, and it has
        // to happen before the comparison below or each would look like a change to the
        // other.
        match desired.entry((resolved.zone.clone(), resolved.key.clone())) {
            std::collections::hash_map::Entry::Occupied(mut existing) => {
                let existing = existing.get_mut();
                existing.records.extend(resolved.records);
                existing.ttl = existing.ttl.min(resolved.ttl);
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(resolved);
            }
        }
    }

    let mut deletes: Vec<(String, RrKey)> = Vec::new();
    for endpoint in &changes.delete {
        let Some(resolved) = resolve(endpoint, zones, &mut tally) else {
            continue;
        };
        let target = (resolved.zone, resolved.key);
        // A delete and a create for the same RRset is a retype or a value change. The
        // desired state wins; this is exactly the case the single atomic request exists
        // for.
        if !desired.contains_key(&target) {
            deletes.push(target);
        }
    }

    let mut by_zone: HashMap<String, ZonePlan> = HashMap::new();

    for ((zone_name, key), resolved) in &desired {
        let Some(zone) = zones.get(zone_name) else {
            continue;
        };
        let value = RrValue::new(resolved.records.iter().cloned(), resolved.ttl);

        if zone.rrsets.get(key) == Some(&value) {
            tally.identical += 1;
            continue;
        }

        let patch = BulkPatch::new(key.subname.clone(), key.record_type.clone())
            .ttl(value.ttl)
            .records(value.records().to_vec());
        entry_for(&mut by_zone, zone).patches.push(patch);
    }

    for (zone_name, key) in &deletes {
        let Some(zone) = zones.get(zone_name) else {
            continue;
        };
        if !zone.rrsets.contains_key(key) {
            tally.delete_absent += 1;
            continue;
        }

        let plan = entry_for(&mut by_zone, zone);
        plan.patches.push(BulkPatch::delete(
            key.subname.clone(),
            key.record_type.clone(),
        ));
        plan.deleted.push(key.clone());
    }

    // Deterministic order, so a retry after a partial apply resumes where it stopped
    // rather than starting over and starving the tail of the list.
    let mut zones: Vec<ZonePlan> = by_zone.into_values().collect();
    zones.sort_by(|a, b| a.zone.cmp(&b.zone));

    Plan { zones, tally }
}

fn entry_for<'a>(by_zone: &'a mut HashMap<String, ZonePlan>, zone: &Zone) -> &'a mut ZonePlan {
    by_zone
        .entry(zone.name.clone())
        .or_insert_with(|| ZonePlan {
            zone: zone.name.clone(),
            patches: Vec::new(),
            deleted: Vec::new(),
        })
}

/// Place an endpoint in a zone, or count why it cannot be placed.
fn resolve(endpoint: &Endpoint, zones: &ZoneIndex, tally: &mut Tally) -> Option<Resolved> {
    let dns_name = canonical_name(&endpoint.dns_name);

    let Some(zone) = zones.zone_for(&dns_name) else {
        tally.no_managed_zone += 1;
        // Rate-limited by being once per endpoint per cycle rather than per retry, and
        // worth the noise: this is what a misconfigured --txt-prefix looks like from here,
        // and the sync will never converge until it is fixed.
        tracing::warn!(
            dns_name = %dns_name,
            record_type = %endpoint.record_type.as_str(),
            "skipping change: no managed deSEC zone contains this name. If this is an \
             ownership record for a zone apex, set --txt-prefix=externaldns-%{{record_type}}. \
             on external-dns"
        );
        return None;
    };

    let record_type = record_type_of(&endpoint.record_type).or_else(|| {
        tally.unusable += 1;
        tracing::warn!(
            dns_name = %dns_name,
            record_type = %endpoint.record_type.as_str(),
            "skipping change: deSEC will not accept this record type"
        );
        None
    })?;

    let subname = subname_within(&dns_name, &zone.name).or_else(|| {
        tally.unusable += 1;
        tracing::warn!(dns_name = %dns_name, zone = %zone.name, "skipping change: not a valid subname");
        None
    })?;

    // Clamped here as well as in adjustment, because ownership records never went through
    // adjustment: the TXT registry generates them in ApplyChanges, with TTL 0.
    let ttl = clamp_ttl(endpoint.record_ttl, zone.minimum_ttl);
    let ttl = u32::try_from(ttl.0).ok()?;

    Some(Resolved {
        zone: zone.name.clone(),
        key: RrKey::new(subname, record_type.clone()),
        ttl,
        records: records_for(&record_type, &endpoint.targets),
    })
}

/// The subname and type a patch addresses, for tests and for logging.
pub fn patch_key(patch: &BulkPatch) -> (Subname, RecordType) {
    (patch.subname.clone(), patch.record_type.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{RecordTypeName, Ttl};
    use std::time::Instant;

    fn zone(name: &str, rrsets: &[(&str, RecordType, u32, &[&str])]) -> Zone {
        Zone {
            name: name.to_owned(),
            minimum_ttl: 3600,
            touched: None,
            rrsets: rrsets
                .iter()
                .map(|(subname, record_type, ttl, records)| {
                    (
                        RrKey::new(
                            Subname::new(*subname).expect("valid subname"),
                            record_type.clone(),
                        ),
                        RrValue::new(records.iter().map(|r| (*r).to_owned()), *ttl),
                    )
                })
                .collect(),
            listed_at: Instant::now(),
            write_epoch: 0,
        }
    }

    fn endpoint(dns_name: &str, record_type: &str, ttl: i64, targets: &[&str]) -> Endpoint {
        Endpoint {
            dns_name: dns_name.to_owned(),
            targets: targets.iter().map(|t| (*t).to_owned()).collect(),
            record_type: RecordTypeName::new(record_type),
            record_ttl: Ttl(ttl),
            ..Endpoint::default()
        }
    }

    fn keys(plan: &ZonePlan) -> Vec<(String, String)> {
        let mut keys: Vec<(String, String)> = plan
            .patches
            .iter()
            .map(|patch| {
                let (subname, record_type) = patch_key(patch);
                (
                    subname.as_payload().to_owned(),
                    record_type.as_str().to_owned(),
                )
            })
            .collect();
        keys.sort();
        keys
    }

    /// The wedge this design exists to avoid. A→CNAME arrives as a delete plus a create;
    /// only one atomic request can express it, because deSEC rejects the intermediate
    /// state in either order.
    #[test]
    fn a_record_type_change_becomes_one_atomic_request() {
        let zones: ZoneIndex = [zone(
            "example.com",
            &[("www", RecordType::A, 3600, &["192.0.2.1"])],
        )]
        .into_iter()
        .collect();

        let plan = build(
            &Changes {
                create: vec![endpoint(
                    "www.example.com",
                    "CNAME",
                    3600,
                    &["target.example.org"],
                )],
                delete: vec![endpoint("www.example.com", "A", 3600, &["192.0.2.1"])],
                ..Changes::default()
            },
            &zones,
        );

        assert_eq!(plan.zones.len(), 1, "one request, not two");
        assert_eq!(
            keys(&plan.zones[0]),
            vec![
                ("www".to_owned(), "A".to_owned()),
                ("www".to_owned(), "CNAME".to_owned()),
            ],
            "both the removal and the creation are in it"
        );
        assert_eq!(plan.zones[0].deleted.len(), 1);
    }

    /// The suppression that retires the 1440-writes-a-day bug even if something upstream
    /// starts asking for spurious updates again.
    #[test]
    fn an_update_that_changes_nothing_makes_no_request() {
        let zones: ZoneIndex = [zone(
            "example.com",
            &[("www", RecordType::A, 3600, &["192.0.2.1"])],
        )]
        .into_iter()
        .collect();

        let plan = build(
            &Changes {
                update_old: vec![endpoint("www.example.com", "A", 3600, &["192.0.2.1"])],
                update_new: vec![endpoint("www.example.com", "A", 3600, &["192.0.2.1"])],
                ..Changes::default()
            },
            &zones,
        );

        assert!(plan.is_empty(), "no zone should be written to");
        assert_eq!(plan.tally.identical, 1);
    }

    #[test]
    fn target_order_and_duplication_do_not_count_as_a_change() {
        let zones: ZoneIndex = [zone(
            "example.com",
            &[("www", RecordType::A, 3600, &["192.0.2.1", "192.0.2.2"])],
        )]
        .into_iter()
        .collect();

        let plan = build(
            &Changes {
                update_new: vec![endpoint(
                    "www.example.com",
                    "A",
                    3600,
                    &["192.0.2.2", "192.0.2.1", "192.0.2.2"],
                )],
                ..Changes::default()
            },
            &zones,
        );

        assert!(plan.is_empty());
        assert_eq!(plan.tally.identical, 1);
    }

    /// An ownership record for a zone apex is generated with TTL 0, after adjustment, so
    /// the write path is the only place it can be clamped.
    #[test]
    fn a_change_arriving_without_a_ttl_is_clamped_here_too() {
        let zones: ZoneIndex = [zone("example.com", &[])].into_iter().collect();

        let plan = build(
            &Changes {
                create: vec![endpoint(
                    "externaldns-a.example.com",
                    "TXT",
                    0,
                    &["heritage=external-dns"],
                )],
                ..Changes::default()
            },
            &zones,
        );

        assert_eq!(plan.rrset_count(), 1);
        // Not zero, which deSEC rejects, and not a hardcoded value either.
        assert_eq!(
            serde_json::to_value(&plan.zones[0].patches[0]).expect("serializes")["ttl"],
            serde_json::json!(3600)
        );
    }

    /// The apex-ownership artefact: a name in the parent zone, which no deSEC account of
    /// ours can hold. Skipped rather than failed, so the rest of the cycle still applies.
    #[test]
    fn a_change_outside_every_managed_zone_is_skipped_not_failed() {
        let zones: ZoneIndex = [zone("example.com", &[])].into_iter().collect();

        let plan = build(
            &Changes {
                create: vec![
                    endpoint("externaldns-a-example.com", "TXT", 3600, &["heritage=x"]),
                    endpoint("ok.example.com", "A", 3600, &["192.0.2.1"]),
                ],
                ..Changes::default()
            },
            &zones,
        );

        assert_eq!(plan.rrset_count(), 1);
        assert_eq!(plan.tally.no_managed_zone, 1);
    }

    #[test]
    fn deleting_something_that_is_not_there_makes_no_request() {
        let zones: ZoneIndex = [zone("example.com", &[])].into_iter().collect();

        let plan = build(
            &Changes {
                delete: vec![endpoint("gone.example.com", "A", 3600, &["192.0.2.1"])],
                ..Changes::default()
            },
            &zones,
        );

        assert!(plan.is_empty());
        assert_eq!(plan.tally.delete_absent, 1);
    }

    #[test]
    fn a_deletion_is_encoded_as_an_empty_record_list() {
        let zones: ZoneIndex = [zone(
            "example.com",
            &[("old", RecordType::A, 3600, &["192.0.2.1"])],
        )]
        .into_iter()
        .collect();

        let plan = build(
            &Changes {
                delete: vec![endpoint("old.example.com", "A", 3600, &["192.0.2.1"])],
                ..Changes::default()
            },
            &zones,
        );

        let body = serde_json::to_value(&plan.zones[0].patches[0]).expect("serializes");
        assert_eq!(body["records"], serde_json::json!([]));
    }

    /// deSEC has one RRset per (subname, type) and no notion of a set identifier, so
    /// endpoints that differ only by one have to be merged rather than racing each other.
    #[test]
    fn endpoints_differing_only_by_set_identifier_merge_into_one_rrset() {
        let zones: ZoneIndex = [zone("example.com", &[])].into_iter().collect();

        let plan = build(
            &Changes {
                create: vec![
                    Endpoint {
                        set_identifier: "a".to_owned(),
                        ..endpoint("www.example.com", "A", 3600, &["192.0.2.1"])
                    },
                    Endpoint {
                        set_identifier: "b".to_owned(),
                        ..endpoint("www.example.com", "A", 3600, &["192.0.2.2"])
                    },
                ],
                ..Changes::default()
            },
            &zones,
        );

        assert_eq!(plan.rrset_count(), 1);
        assert_eq!(
            serde_json::to_value(&plan.zones[0].patches[0]).expect("serializes")["records"],
            serde_json::json!(["192.0.2.1", "192.0.2.2"])
        );
    }

    #[test]
    fn each_zone_gets_its_own_request_in_a_deterministic_order() {
        let zones: ZoneIndex = [zone("b.example.org", &[]), zone("a.example.com", &[])]
            .into_iter()
            .collect();

        let plan = build(
            &Changes {
                create: vec![
                    endpoint("x.b.example.org", "A", 3600, &["192.0.2.1"]),
                    endpoint("x.a.example.com", "A", 3600, &["192.0.2.1"]),
                ],
                ..Changes::default()
            },
            &zones,
        );

        assert_eq!(
            plan.zones
                .iter()
                .map(|z| z.zone.as_str())
                .collect::<Vec<_>>(),
            vec!["a.example.com", "b.example.org"]
        );
    }

    #[test]
    fn a_change_to_the_apex_addresses_the_empty_subname() {
        let zones: ZoneIndex = [zone("example.com", &[])].into_iter().collect();

        let plan = build(
            &Changes {
                create: vec![endpoint("example.com", "A", 3600, &["192.0.2.1"])],
                ..Changes::default()
            },
            &zones,
        );

        let body = serde_json::to_value(&plan.zones[0].patches[0]).expect("serializes");
        // Present and empty. Omitting it is a 400 from deSEC, and an `omitempty` tag on
        // this field is what stopped the previous provider creating apex records at all.
        assert_eq!(body["subname"], serde_json::json!(""));
    }

    #[test]
    fn an_empty_change_set_plans_nothing() {
        let zones: ZoneIndex = [zone("example.com", &[])].into_iter().collect();
        let plan = build(&Changes::default(), &zones);

        assert!(plan.is_empty());
        assert_eq!(plan.tally, Tally::default());
    }
}
