//! `/adjustendpoints`: making external-dns's desired state agree with what deSEC will
//! store, before external-dns compares the two.
//!
//! This is the endpoint that fixes the write loop at its source, and it does so without
//! touching the network. external-dns calls it on the *source* endpoints, before the plan
//! is calculated (`controller.go`: `Registry.AdjustEndpoints(sourceEndpoints)`, which the
//! TXT registry passes straight through to the provider). So whatever we return here is
//! what external-dns will diff against the records we report — and any difference it finds
//! becomes a write.
//!
//! The previous provider left `recordTTL: 0` alone here and rewrote it to 3600 only when
//! writing. external-dns therefore compared 0 against 3600 on every cycle, forever, and
//! asked for an update every time: 1440 writes a day against a budget of 300.
//!
//! Note what this endpoint does *not* see. The TXT registry generates its ownership
//! records in `ApplyChanges`, after the plan, so they arrive only at `POST /records`. The
//! out-of-zone check here catches a misconfigured source; the one in `plan` catches the
//! apex-ownership-record artefact.

use desec::api::rrsets::MAX_TTL;

use crate::convert::{canonical_name, record_type_of};
use crate::model::ZoneIndex;
use crate::wire::{Endpoint, Ttl};

/// What adjustment changed, for metrics. Counted rather than logged per endpoint: a large
/// cluster adjusts hundreds of endpoints per cycle.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    /// TTL raised to the zone's floor or lowered to deSEC's ceiling.
    pub ttl_clamped: u64,
    /// A name that was not already canonical.
    pub name_canonicalized: u64,
    /// An RDATA name field that was not already canonical.
    pub rdata_canonicalized: u64,
    /// Dropped: no managed zone contains this name.
    pub dropped_no_zone: u64,
    /// Dropped: deSEC could not accept this record type at all.
    pub dropped_bad_type: u64,
}

impl Tally {
    pub fn dropped(&self) -> u64 {
        self.dropped_no_zone + self.dropped_bad_type
    }
}

/// Normalize the endpoints external-dns intends to create.
///
/// Infallible on purpose. Every outcome is either an adjusted endpoint or a dropped one
/// with a reason; there is no failure mode worth a 5xx, and the previous provider's
/// signature returned an error it never populated.
pub fn adjust(mut endpoints: Vec<Endpoint>, zones: &ZoneIndex) -> (Vec<Endpoint>, Tally) {
    let mut tally = Tally::default();

    // Mutate in place rather than rebuilding each endpoint field by field. `labels`,
    // `setIdentifier` and `providerSpecific` have to come back exactly as they arrived —
    // external-dns's plan compares them — and a constructor listing the fields it knows
    // about silently drops the next one external-dns adds.
    endpoints.retain_mut(|endpoint| adjust_one(endpoint, zones, &mut tally));

    (endpoints, tally)
}

fn adjust_one(endpoint: &mut Endpoint, zones: &ZoneIndex, tally: &mut Tally) -> bool {
    let canonical = canonical_name(&endpoint.dns_name);
    if canonical != endpoint.dns_name {
        tally.name_canonicalized += 1;
        endpoint.dns_name = canonical;
    }

    let Some(zone) = zones.zone_for(&endpoint.dns_name) else {
        tally.dropped_no_zone += 1;
        tracing::warn!(
            dns_name = %endpoint.dns_name,
            "dropping endpoint: no managed deSEC zone contains this name"
        );
        return false;
    };

    let Some(record_type) = record_type_of(&endpoint.record_type) else {
        tally.dropped_bad_type += 1;
        tracing::warn!(
            dns_name = %endpoint.dns_name,
            record_type = %endpoint.record_type.as_str(),
            "dropping endpoint: deSEC will not accept this record type"
        );
        return false;
    };

    // The zone's own floor, read from the API. Assuming 3600 would be the same bug as not
    // clamping at all on a zone whose minimum differs.
    let clamped = clamp_ttl(endpoint.record_ttl, zone.minimum_ttl);
    if clamped != endpoint.record_ttl {
        tally.ttl_clamped += 1;
        endpoint.record_ttl = clamped;
    }

    // RDATA names have to arrive in the same shape we report them in, or external-dns
    // sees a difference between a CNAME target it asked for and the one we hold.
    for target in &mut endpoint.targets {
        let canonical = crate::convert::canonical_rdata(&record_type, target);
        if canonical != *target {
            tally.rdata_canonicalized += 1;
            *target = canonical;
        }
    }

    true
}

/// The TTL deSEC will actually store for this zone.
///
/// `0` from a source means "you decide" — Kubernetes objects have no TTL, so most sources
/// emit it — and anything below the zone's floor or above deSEC's ceiling would be
/// silently changed on write. Deciding here is what makes external-dns's comparison agree
/// with storage.
///
/// Also needed on the write path, not just here. The TXT registry builds its ownership
/// records with `endpoint.NewEndpoint`, which is `NewEndpointWithTTL(…, TTL(0), …)`, and
/// it does so in `ApplyChanges` — after adjustment. So every ownership record reaches
/// `POST /records` with no TTL at all.
pub fn clamp_ttl(requested: Ttl, minimum_ttl: u32) -> Ttl {
    let floor = i64::from(minimum_ttl);
    let ceiling = i64::from(MAX_TTL);

    if requested.is_unset() {
        return Ttl(floor);
    }
    Ttl(requested.0.clamp(floor, ceiling))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::{endpoint_from_rrset, records_for, subname_within};
    use crate::model::Zone;
    use crate::wire::{ProviderSpecificProperty, RecordTypeName};
    use proptest::prelude::*;
    use std::collections::{BTreeMap, HashMap};
    use std::time::Instant;

    fn zones(specs: &[(&str, u32)]) -> ZoneIndex {
        specs
            .iter()
            .map(|(name, minimum_ttl)| Zone {
                name: (*name).to_owned(),
                minimum_ttl: *minimum_ttl,
                touched: None,
                rrsets: HashMap::new(),
                listed_at: Instant::now(),
                write_epoch: 0,
            })
            .collect()
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

    /// The root cause of the 1440-writes-a-day bug: a source that emits no TTL.
    #[test]
    fn an_unset_ttl_becomes_the_zones_own_minimum() {
        let zones = zones(&[("example.com", 3600), ("low.example.org", 60)]);
        let (adjusted, tally) = adjust(
            vec![
                endpoint("a.example.com", "A", 0, &["192.0.2.1"]),
                endpoint("a.low.example.org", "A", 0, &["192.0.2.1"]),
            ],
            &zones,
        );

        assert_eq!(adjusted[0].record_ttl, Ttl(3600));
        // Not a hardcoded 3600: this zone's floor is lower, and clamping to 3600 would
        // make external-dns disagree with what deSEC stores just as badly.
        assert_eq!(adjusted[1].record_ttl, Ttl(60));
        assert_eq!(tally.ttl_clamped, 2);
    }

    #[test]
    fn a_ttl_inside_the_permitted_range_is_left_alone() {
        let zones = zones(&[("example.com", 3600)]);
        let (adjusted, tally) = adjust(
            vec![endpoint("a.example.com", "A", 7200, &["192.0.2.1"])],
            &zones,
        );

        assert_eq!(adjusted[0].record_ttl, Ttl(7200));
        assert_eq!(tally.ttl_clamped, 0);
    }

    #[test]
    fn a_ttl_outside_desecs_range_is_clamped_at_both_ends() {
        let zones = zones(&[("example.com", 3600)]);
        let (adjusted, _) = adjust(
            vec![
                endpoint("low.example.com", "A", 300, &["192.0.2.1"]),
                endpoint("high.example.com", "A", 999_999, &["192.0.2.1"]),
                endpoint("neg.example.com", "A", -5, &["192.0.2.1"]),
            ],
            &zones,
        );

        assert_eq!(adjusted[0].record_ttl, Ttl(3600));
        assert_eq!(adjusted[1].record_ttl, Ttl(i64::from(MAX_TTL)));
        assert_eq!(adjusted[2].record_ttl, Ttl(3600));
    }

    #[test]
    fn a_name_outside_every_managed_zone_is_dropped_not_failed() {
        let zones = zones(&[("example.com", 3600)]);
        let (adjusted, tally) = adjust(
            vec![
                endpoint("a.example.com", "A", 3600, &["192.0.2.1"]),
                endpoint("a.example.org", "A", 3600, &["192.0.2.1"]),
            ],
            &zones,
        );

        assert_eq!(adjusted.len(), 1);
        assert_eq!(adjusted[0].dns_name, "a.example.com");
        assert_eq!(tally.dropped_no_zone, 1);
    }

    #[test]
    fn the_longest_matching_zone_supplies_the_ttl_floor() {
        // Delegated child with a different floor from its parent.
        let zones = zones(&[("dedyn.io", 3600), ("sub.dedyn.io", 60)]);
        let (adjusted, _) = adjust(
            vec![endpoint("service.sub.dedyn.io", "A", 0, &["192.0.2.1"])],
            &zones,
        );

        assert_eq!(adjusted[0].record_ttl, Ttl(60));
    }

    /// The fields external-dns's plan compares and we must not touch. A constructor that
    /// listed fields by hand would drop whichever one external-dns adds next.
    #[test]
    fn everything_we_do_not_normalize_comes_back_byte_identical() {
        let zones = zones(&[("example.com", 3600)]);
        let original = Endpoint {
            dns_name: "a.example.com".to_owned(),
            targets: vec!["192.0.2.1".to_owned()],
            record_type: RecordTypeName::new("A"),
            set_identifier: "weighted-1".to_owned(),
            record_ttl: Ttl(3600),
            labels: BTreeMap::from([
                ("owner".to_owned(), "cluster-1".to_owned()),
                ("resource".to_owned(), "ingress/default/web".to_owned()),
            ]),
            provider_specific: vec![
                ProviderSpecificProperty {
                    name: "dup".to_owned(),
                    value: "first".to_owned(),
                },
                ProviderSpecificProperty {
                    name: "dup".to_owned(),
                    value: "second".to_owned(),
                },
            ],
        };

        let (adjusted, tally) = adjust(vec![original.clone()], &zones);

        assert_eq!(adjusted, vec![original]);
        assert_eq!(tally, Tally::default());
    }

    #[test]
    fn a_record_type_desec_cannot_accept_is_dropped_with_its_own_reason() {
        let zones = zones(&[("example.com", 3600)]);
        let (adjusted, tally) = adjust(
            vec![endpoint("a.example.com", "not a type!", 3600, &["x"])],
            &zones,
        );

        assert!(adjusted.is_empty());
        assert_eq!(tally.dropped_bad_type, 1);
        assert_eq!(tally.dropped_no_zone, 0);
    }

    #[test]
    fn a_type_this_build_does_not_name_survives_adjustment() {
        let zones = zones(&[("example.com", 3600)]);
        let (adjusted, tally) = adjust(
            vec![endpoint("a.example.com", "WALLET", 3600, &["whatever"])],
            &zones,
        );

        assert_eq!(adjusted.len(), 1);
        assert_eq!(adjusted[0].record_type.as_str(), "WALLET");
        assert_eq!(tally.dropped(), 0);
    }

    #[test]
    fn a_cname_target_is_reported_the_way_we_will_report_it() {
        let zones = zones(&[("example.com", 3600)]);
        let (adjusted, tally) = adjust(
            vec![endpoint(
                "a.example.com",
                "CNAME",
                3600,
                &["Alias.Example.ORG."],
            )],
            &zones,
        );

        assert_eq!(adjusted[0].targets, vec!["alias.example.org".to_owned()]);
        assert_eq!(tally.rdata_canonicalized, 1);
    }

    /// Idempotence. If adjusting twice differed from adjusting once, external-dns would
    /// see a change on the cycle after the one that fixed it, forever.
    #[test]
    fn adjustment_is_idempotent() {
        let zones = zones(&[("example.com", 3600)]);
        let inputs = vec![
            endpoint("A.Example.COM.", "A", 0, &["192.0.2.1"]),
            endpoint("b.example.com", "CNAME", 100, &["Target.Example.ORG."]),
            endpoint("c.example.com", "MX", 99_999, &["10 Mail.Example.ORG."]),
            endpoint("d.example.com", "TXT", 0, &["heritage=external-dns"]),
        ];

        let (once, _) = adjust(inputs, &zones);
        let (twice, tally) = adjust(once.clone(), &zones);

        assert_eq!(once, twice);
        assert_eq!(tally, Tally::default(), "a settled input changes nothing");
    }

    /// The other half of the same guarantee: what we adjust, store and read back is what
    /// we adjusted. Together these two make a no-op write loop unrepresentable, which is
    /// stronger than fixing each of the three bugs that caused one.
    #[test]
    fn adjusting_storing_and_reading_back_is_a_fixpoint() {
        let zones = zones(&[("example.com", 3600)]);
        let inputs = vec![
            endpoint("a.example.com", "A", 0, &["192.0.2.1"]),
            endpoint("example.com", "A", 0, &["192.0.2.2"]),
            endpoint("b.example.com", "CNAME", 0, &["target.example.org"]),
            endpoint("c.example.com", "MX", 0, &["10 mail.example.org"]),
            endpoint(
                "d.example.com",
                "TXT",
                0,
                &["heritage=external-dns,owner=x"],
            ),
            endpoint("e.example.com", "TXT", 0, &[&"long-".repeat(80)]),
            endpoint("f.example.com", "SRV", 0, &["10 20 443 host.example.org"]),
            endpoint("g.example.com", "CAA", 0, &["0 issue \"letsencrypt.org\""]),
        ];

        let (adjusted, _) = adjust(inputs, &zones);

        for endpoint in &adjusted {
            let record_type = record_type_of(&endpoint.record_type).expect("adjusted");
            let subname = subname_within(&endpoint.dns_name, "example.com").expect("in zone");
            let stored = records_for(&record_type, &endpoint.targets);

            let read_back = endpoint_from_rrset(
                "example.com",
                &serde_json::from_value(serde_json::json!({
                    "domain": "example.com",
                    "subname": subname.as_payload(),
                    "type": record_type.as_str(),
                    "name": "ignored.",
                    "records": stored,
                    "ttl": u32::try_from(endpoint.record_ttl.0).expect("clamped into range"),
                    "created": "2026-01-01T00:00:00Z",
                    "touched": "2026-01-01T00:00:00Z",
                }))
                .expect("valid rrset"),
            );

            assert_eq!(read_back.dns_name, endpoint.dns_name);
            assert_eq!(read_back.targets, endpoint.targets, "{}", endpoint.dns_name);
            assert_eq!(read_back.record_ttl, endpoint.record_ttl);

            // And adjusting what we read back changes nothing further.
            let (settled, tally) = adjust(vec![read_back], &zones);
            assert_eq!(settled.len(), 1);
            assert_eq!(tally, Tally::default(), "{}", endpoint.dns_name);
        }
    }

    proptest! {
        #[test]
        fn clamping_always_lands_in_the_range_desec_accepts(
            requested in -1000i64..200_000,
            minimum_ttl in 1u32..=MAX_TTL,
        ) {
            let clamped = clamp_ttl(Ttl(requested), minimum_ttl).0;
            prop_assert!(clamped >= i64::from(minimum_ttl));
            prop_assert!(clamped <= i64::from(MAX_TTL));
            // And clamping a clamped value is a no-op.
            prop_assert_eq!(clamp_ttl(Ttl(clamped), minimum_ttl).0, clamped);
        }
    }
}
