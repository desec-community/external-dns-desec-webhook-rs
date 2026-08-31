//! The probe table in external-dns's form, and what this webhook must do with each value.
//!
//! Paired with `desec::probes`, which holds the same probes in deSEC's presentation form
//! together with what the API measurably does to them. The identifiers are the contract
//! between the two tables: [`every_probe_is_accounted_for`] asserts that every id here
//! exists there and that every id there is either mirrored or listed in [`SKIPPED`] with a
//! reason, so the two cannot drift apart silently.
//!
//! The *values* deliberately differ. `desec::probes` sends what it wants deSEC to see; this
//! table sends what an external-dns source would emit, and `convert::records_for` decides
//! what actually goes on the wire. For a name-bearing type those are not the same string,
//! because `records_for` lowercases and qualifies the name. So `Alias.Example.ORG` here
//! becomes `alias.example.org.` on the wire, where the upstream table sends
//! `Alias.Example.ORG.` unchanged. Same phenomenon, different input.
//!
//! # Why the outcomes are not all `Fixpoint`
//!
//! deSEC rewrites record values on storage. Whether that costs anything depends on what sits
//! between the source and the comparison, and there turn out to be three different answers,
//! which is why [`Outcome`] has four variants rather than a boolean.

#![allow(dead_code)]

/// What this webhook does with a probe once deSEC has had its way with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// deSEC stores it as sent, and we report back what external-dns asked for.
    Fixpoint,

    /// deSEC rewrites it, but our own egress maps it back, so external-dns never sees a
    /// difference and never asks for a write. The string says how.
    Rejoined(&'static str),

    /// deSEC rewrites it, our egress does not map it back, but external-dns's own target
    /// comparison absorbs the difference. The string names what absorbs it.
    ///
    /// A dependency on external-dns internals rather than on anything here, which is exactly
    /// why it is written down rather than left as a passing test.
    Absorbed(&'static str),

    /// deSEC rewrites it, nothing absorbs the difference, and external-dns therefore asks for
    /// the same write on every reconcile. A known defect.
    ///
    /// Pinned rather than tolerated: the live test asserts the loop is still there, so fixing
    /// one of these fails its row and forces the classification to be revisited.
    Loops(&'static str),
}

impl Outcome {
    /// Whether deSEC stores something other than what `records_for` produced.
    ///
    /// Drives the cross-check against `ApplyReport::normalized`, which is the same question
    /// asked by the production code rather than by the table.
    pub fn is_rewritten(self) -> bool {
        !matches!(self, Self::Fixpoint)
    }

    /// Whether external-dns will keep asking for this write forever.
    pub fn loops(self) -> bool {
        matches!(self, Self::Loops(_))
    }
}

/// One probe, as a source would hand it to `/adjustendpoints`.
pub struct WebhookProbe {
    /// Matches an id in `desec::probes::PROBES`.
    pub id: &'static str,
    /// Label within the scratch zone. Kept here rather than read from the upstream table so
    /// this file reads on its own, and cross-checked against it by a test.
    pub subname: &'static str,
    /// Record type mnemonic, as external-dns spells it.
    pub record_type: &'static str,
    /// One target, in external-dns's form: embedded names bare, text values unquoted.
    pub target: &'static str,
    pub outcome: Outcome,
}

/// Absorbed by external-dns comparing targets case-insensitively, before it ever reaches the
/// IP-parsing fallback.
const EQUAL_FOLD: &str = "external-dns Targets.Same compares targets with strings.EqualFold";

/// Absorbed by external-dns parsing both sides as addresses when the string compare fails.
const PARSE_ADDR: &str = "external-dns Targets.Same falls back to netip.ParseAddr";

/// The probes, in the same order as `desec::probes::PROBES`.
pub const WEBHOOK_PROBES: &[WebhookProbe] = &[
    WebhookProbe {
        id: "a-control",
        subname: "a",
        record_type: "A",
        target: "192.0.2.1",
        outcome: Outcome::Fixpoint,
    },
    // The four AAAA forms all survive for the same reason, and none of it is our doing:
    // deSEC recompresses, we report the recompressed form, and external-dns notices the two
    // are the same address. Rust's `Ipv6Addr` would reproduce three of the four; the mapped
    // form it would not, because deSEC renders an embedded IPv4 address as hex.
    WebhookProbe {
        id: "aaaa-expanded",
        subname: "aaaa",
        record_type: "AAAA",
        target: "2001:0DB8:0000:0000:0000:0000:0000:0001",
        outcome: Outcome::Absorbed(PARSE_ADDR),
    },
    WebhookProbe {
        id: "aaaa-v4mapped-dotted",
        subname: "aaaa-v4m",
        record_type: "AAAA",
        target: "::ffff:192.0.2.1",
        outcome: Outcome::Absorbed(PARSE_ADDR),
    },
    WebhookProbe {
        id: "aaaa-v4mapped-hex",
        subname: "aaaa-v4h",
        record_type: "AAAA",
        target: "::ffff:c000:0201",
        outcome: Outcome::Absorbed(PARSE_ADDR),
    },
    WebhookProbe {
        id: "aaaa-v4compat-dotted",
        subname: "aaaa-v4c",
        record_type: "AAAA",
        target: "::192.0.2.1",
        outcome: Outcome::Absorbed(PARSE_ADDR),
    },
    // Mixed case survives because we never send it: `records_for` lowercases the name field
    // on the way in and `canonical_rdata` lowercases it on the way out, so both sides of
    // external-dns's comparison see the same lowercased form. deSEC would have preserved
    // whatever case we sent.
    WebhookProbe {
        id: "cname-case",
        subname: "cname",
        record_type: "CNAME",
        target: "Alias.Example.ORG",
        outcome: Outcome::Fixpoint,
    },
    WebhookProbe {
        id: "mx-case",
        subname: "mx",
        record_type: "MX",
        target: "10 Mail.Example.ORG",
        outcome: Outcome::Fixpoint,
    },
    WebhookProbe {
        id: "srv-name",
        subname: "_sip._tcp.srv",
        record_type: "SRV",
        target: "10 20 5060 Sip.Example.ORG",
        outcome: Outcome::Fixpoint,
    },
    WebhookProbe {
        id: "ns-sub",
        subname: "deleg",
        record_type: "NS",
        target: "Ns1.Example.ORG",
        outcome: Outcome::Fixpoint,
    },
    // Hex digests: deSEC lowercases and we pass both directions through untouched, so the
    // reported value differs from the source's by case alone. `EqualFold` is what saves it.
    WebhookProbe {
        id: "ds-sub",
        subname: "deleg",
        record_type: "DS",
        target: "12345 13 2 3A5B7C9D1E2F4A6B8C0D2E4F6A8B0C1D3E5F7A9B1C3D5E7F9A0B2C4D6E8F0A1B",
        outcome: Outcome::Absorbed(EQUAL_FOLD),
    },
    WebhookProbe {
        id: "ptr-case",
        subname: "ptr",
        record_type: "PTR",
        target: "Host.Example.ORG",
        outcome: Outcome::Fixpoint,
    },
    // The one that vindicates emitting a single character-string and letting deSEC split:
    // it comes back as two, and `txt_unquote` rejoins them, so external-dns sees the value
    // it asked for. `docs/testing.md` used to call this the open question of the design.
    WebhookProbe {
        id: "txt-long",
        subname: "txt-long",
        record_type: "TXT",
        target: TXT_300_PLAIN,
        outcome: Outcome::Rejoined("convert::txt_unquote joins the character-strings back up"),
    },
    // Sent as raw UTF-8 rather than as `\DDD` escapes, which is what a Kubernetes annotation
    // holds. If deSEC re-escapes it, `txt_unquote` decodes the octets back, so this stays a
    // fixpoint either way — and if it does not decode to UTF-8, `txt_unquote` says so rather
    // than corrupting it.
    WebhookProbe {
        id: "txt-escapes",
        subname: "txt-esc",
        record_type: "TXT",
        target: r#"has "quotes" and \ backslash and unicode: ü"#,
        outcome: Outcome::Fixpoint,
    },
    WebhookProbe {
        id: "spf-quoted",
        subname: "spf",
        record_type: "SPF",
        target: "v=spf1 include:_spf.example.org -all",
        outcome: Outcome::Fixpoint,
    },
    WebhookProbe {
        id: "caa-tag-case",
        subname: "caa",
        record_type: "CAA",
        target: r#"0 ISSUE "letsencrypt.org""#,
        outcome: Outcome::Fixpoint,
    },
    WebhookProbe {
        id: "naptr-flag-case",
        subname: "naptr",
        record_type: "NAPTR",
        target: r#"100 10 "S" "SIP+D2U" "" _sip._udp.Example.ORG"#,
        outcome: Outcome::Fixpoint,
    },
    WebhookProbe {
        id: "tlsa-hex-case",
        subname: "_443._tcp.tlsa",
        record_type: "TLSA",
        target: "3 1 1 3A5B7C9D1E2F4A6B8C0D2E4F6A8B0C1D3E5F7A9B1C3D5E7F9A0B2C4D6E8F0A1B",
        outcome: Outcome::Absorbed(EQUAL_FOLD),
    },
    WebhookProbe {
        id: "sshfp-hex-case",
        subname: "sshfp",
        record_type: "SSHFP",
        target: "2 1 3A5B7C9D1E2F4A6B8C0D2E4F6A8B0C1D3E5F7A9B",
        outcome: Outcome::Absorbed(EQUAL_FOLD),
    },
    WebhookProbe {
        id: "uri-target",
        subname: "_http._tcp.uri",
        record_type: "URI",
        target: r#"10 1 "https://Example.ORG/Path""#,
        outcome: Outcome::Fixpoint,
    },
    // The four defects. `LOC` reformats and quantizes, `SVCB` and `HTTPS` sort parameters
    // and drop quoting; none of it is case-only or parseable as an address, so external-dns
    // compares the reported value against the source's, differs, and asks again next cycle.
    WebhookProbe {
        id: "loc-format",
        subname: "loc",
        record_type: "LOC",
        target: "42 21 54 N 71 06 18 W 24m 30m 10m 10m",
        outcome: Outcome::Loops("deSEC reformats every field: seconds, minutes and distances"),
    },
    WebhookProbe {
        id: "loc-quantized",
        subname: "loc2",
        record_type: "LOC",
        target: "42 21 54 N 71 06 18 W 24m 33m 10m 10m",
        outcome: Outcome::Loops(
            "size is a mantissa-and-exponent byte, so 33m quantizes to 30.00m and no string \
             rewriting could predict it",
        ),
    },
    WebhookProbe {
        id: "svcb-param-order",
        subname: "svcb",
        record_type: "SVCB",
        target: "1 svc.Example.ORG port=443 alpn=h2,h3 ipv6hint=2001:0DB8::1",
        outcome: Outcome::Loops("deSEC sorts parameters into key order and compresses ipv6hint"),
    },
    WebhookProbe {
        id: "https-alias",
        subname: "https",
        record_type: "HTTPS",
        target: "0 Svc.Example.ORG",
        outcome: Outcome::Fixpoint,
    },
    WebhookProbe {
        id: "https-params",
        subname: "https2",
        record_type: "HTTPS",
        target: r#"1 . alpn="h3,h2" no-default-alpn ipv4hint=192.0.2.1,192.0.2.2"#,
        outcome: Outcome::Loops("deSEC drops the quoting from a parameter value"),
    },
];

/// Upstream probes with no external-dns counterpart, and why.
///
/// Listed rather than omitted, so [`every_probe_is_accounted_for`] can insist that adding a
/// probe upstream forces a decision here.
pub const SKIPPED: &[(&str, &str)] = &[(
    "txt-prechunked",
    "no source value produces it: `txt_quote` always emits exactly one character-string, so \
     the webhook can never send author-supplied chunking for deSEC to preserve",
)];

/// The 300-character value of the `txt-long` probe, unquoted — the form a source emits.
///
/// The same payload as `desec::probes`'s version without its enclosing quotes, which
/// [`the_long_txt_probe_matches_upstream`] checks rather than trusts.
const TXT_300_PLAIN: &str = concat!(
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789",
);

/// The probes external-dns will keep asking for, which is what the second and third
/// reconcile passes expect to see written again.
pub fn looping() -> Vec<&'static WebhookProbe> {
    WEBHOOK_PROBES
        .iter()
        .filter(|probe| probe.outcome.loops())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn upstream_ids() -> BTreeSet<&'static str> {
        desec::probes::PROBES.iter().map(|p| p.id).collect()
    }

    /// The contract between the two tables. Adding a probe upstream has to land here or in
    /// [`SKIPPED`], and a typo in an id cannot pass as a missing row.
    #[test]
    fn every_probe_is_accounted_for() {
        let ours: BTreeSet<&str> = WEBHOOK_PROBES.iter().map(|p| p.id).collect();
        let skipped: BTreeSet<&str> = SKIPPED.iter().map(|(id, _)| *id).collect();
        let upstream = upstream_ids();

        assert!(
            ours.is_disjoint(&skipped),
            "a probe cannot be both mirrored and skipped: {:?}",
            &ours & &skipped
        );
        let unknown: Vec<_> = (&ours - &upstream).into_iter().collect();
        assert!(unknown.is_empty(), "not in desec::probes: {unknown:?}");
        let unhandled: Vec<_> = (&upstream - &(&ours | &skipped)).into_iter().collect();
        assert!(
            unhandled.is_empty(),
            "new upstream probes need a row here or an entry in SKIPPED: {unhandled:?}"
        );
    }

    /// The subname and type identify the RRset, so a disagreement would have the two suites
    /// measuring different things under one name.
    #[test]
    fn mirrored_probes_agree_with_upstream_on_where_they_live() {
        for probe in WEBHOOK_PROBES {
            let upstream = desec::probes::PROBES
                .iter()
                .find(|p| p.id == probe.id)
                .expect("checked by every_probe_is_accounted_for");
            assert_eq!(probe.subname, upstream.subname, "{}", probe.id);
            assert_eq!(probe.record_type, upstream.record_type, "{}", probe.id);
        }
    }

    /// Our unquoted form has to be the upstream payload exactly, or the two suites are not
    /// probing the same 300 characters.
    #[test]
    fn the_long_txt_probe_matches_upstream() {
        let upstream = desec::probes::PROBES
            .iter()
            .find(|p| p.id == "txt-long")
            .expect("upstream has txt-long");
        assert_eq!(TXT_300_PLAIN.len(), 300);
        assert_eq!(TXT_300_PLAIN, upstream.wire.trim_matches('"'));
    }

    /// Every record type has to be one `convert` will accept, or the endpoint is dropped in
    /// adjustment and the probe never reaches deSEC at all.
    #[test]
    fn every_record_type_converts() {
        for probe in WEBHOOK_PROBES {
            assert!(
                external_dns_desec_webhook::convert::record_type_of(
                    &external_dns_desec_webhook::wire::RecordTypeName::new(probe.record_type)
                )
                .is_some(),
                "{}",
                probe.id
            );
        }
    }

    /// The four defects, named here so the count cannot drift without a deliberate edit.
    /// This is the set `webhook_write_normalized_total` should be reporting in production.
    #[test]
    fn the_known_write_loops_are_exactly_loc_svcb_and_https_params() {
        let looping: Vec<&str> = looping().iter().map(|p| p.id).collect();
        assert_eq!(
            looping,
            [
                "loc-format",
                "loc-quantized",
                "svcb-param-order",
                "https-params"
            ]
        );
    }
}
