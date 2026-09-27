//! Translation between external-dns endpoints and deSEC RRsets.
//!
//! Every historical bug in the Go provider this replaces lived in this translation, and
//! each had the same shape: a value that means one thing to external-dns and another to
//! deSEC, compared as if it meant the same thing. external-dns then saw a difference that
//! was not there, planned an update, and the provider wrote a record that was already
//! correct — once a minute, against a budget of 300 writes a day.
//!
//! So the discipline here is that both sides are canonicalized before anything is
//! compared, and the two properties in `tests` are what enforce it: adjustment is
//! idempotent, and a round trip through deSEC's representation is lossless.

use desec::api::rrsets::Rrset;
use desec::{RecordType, Subname};

use crate::wire::{Endpoint, RecordTypeName, Ttl};

/// Canonical form for any DNS name we compare or emit: lowercase, no trailing dot.
///
/// external-dns's sources emit `foo.example.com`; deSEC returns `foo.example.com.`. The
/// plan calculator compares those as strings, and the TXT registry reads the mismatch as
/// a stale companion record — it then sets `providerSpecific txt/force-update=true` on
/// every `UpdateOld`, which `plan.providerSpecificChanged()` promotes into an `Update`.
/// That is a write loop from one trailing dot.
pub fn canonical_name(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Which whitespace-separated field of this type's RDATA holds a domain name.
///
/// deSEC stores those fields fully qualified (`mail.example.com.`); external-dns carries
/// them bare. The dot therefore has to be added and removed *positionally*, because it is
/// the target inside `10 mail.example.com.` that carries it, not the whole value.
///
/// Unlisted types — including [`RecordType::Other`] — return `None` and pass through
/// untouched. Guessing wrong here would mean a write loop confined to one record type, so
/// the table names only what is certain.
fn rdata_name_field(record_type: &RecordType) -> Option<usize> {
    match record_type {
        RecordType::CNAME | RecordType::DNAME | RecordType::NS | RecordType::PTR => Some(0),
        RecordType::MX | RecordType::KX | RecordType::AFSDB => Some(1),
        RecordType::HTTPS | RecordType::SVCB => Some(1),
        RecordType::SRV => Some(3),
        RecordType::NAPTR => Some(5),
        // RP holds two names and external-dns never emits it; leaving it alone is safer
        // than handling half of it.
        _ => None,
    }
}

/// Whether this type's content is a quoted character-string rather than structured RDATA.
fn is_text_type(record_type: &RecordType) -> bool {
    matches!(record_type, RecordType::TXT | RecordType::SPF)
}

/// Rewrite the name field of an RDATA value, leaving every other field alone.
fn map_rdata_name(record_type: &RecordType, value: &str, f: impl Fn(&str) -> String) -> String {
    let Some(index) = rdata_name_field(record_type) else {
        return value.to_owned();
    };

    let mut fields: Vec<String> = value.split_whitespace().map(str::to_owned).collect();
    match fields.get_mut(index) {
        Some(field) => *field = f(field),
        // Malformed for its type. Pass it through rather than inventing a field: deSEC
        // stored it, so deSEC will accept it back.
        None => return value.to_owned(),
    }
    fields.join(" ")
}

/// deSEC's TXT presentation form to external-dns's plain value.
///
/// deSEC normalizes TXT content to RFC 1035 character-strings on storage, so what comes
/// back is `"heritage=external-dns,..."` *including* the quotes, and a value over 255
/// bytes comes back as several quoted chunks. external-dns compares the ownership TXT it
/// generated against what we report, byte for byte, so the quotes have to come off and
/// the chunks have to be joined.
///
/// A value whose escapes decode to something that is not UTF-8 is returned in its
/// presentation form untouched. Corrupting a binary TXT record we do not own would be
/// worse than reporting it in a shape external-dns will not recognise, and external-dns
/// only rewrites records its registry claims.
pub fn txt_unquote(presentation: &str) -> String {
    if !presentation.contains('"') {
        // Written by something that did not quote, or by an older version of this
        // provider. Take it as-is.
        return presentation.to_owned();
    }

    let mut out: Vec<u8> = Vec::with_capacity(presentation.len());
    let bytes = presentation.as_bytes();
    let mut index = 0;
    let mut in_string = false;

    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;

        match byte {
            b'"' => in_string = !in_string,
            // Whitespace between chunks is a separator, not content.
            _ if !in_string => {}
            b'\\' if index < bytes.len() => {
                let escaped = &bytes[index..];
                // \DDD is one octet given as exactly three decimal digits.
                if let [a, b, c, ..] = escaped {
                    if a.is_ascii_digit() && b.is_ascii_digit() && c.is_ascii_digit() {
                        let decimal = (u32::from(a - b'0')) * 100
                            + (u32::from(b - b'0')) * 10
                            + u32::from(c - b'0');
                        if let Ok(octet) = u8::try_from(decimal) {
                            out.push(octet);
                            index += 3;
                            continue;
                        }
                    }
                }
                out.push(escaped[0]);
                index += 1;
            }
            other => out.push(other),
        }
    }

    match String::from_utf8(out) {
        Ok(decoded) => decoded,
        Err(_) => {
            tracing::warn!(
                "TXT record does not decode to UTF-8; reporting its presentation form unchanged"
            );
            presentation.to_owned()
        }
    }
}

/// The heritage marker that opens every value external-dns's TXT registry writes.
const OWNERSHIP_PREFIX: &str = "heritage=external-dns";

/// The plain value behind a target external-dns has already put in presentation form.
///
/// Ownership records are the one target that does not arrive as a plain value: the TXT
/// registry builds them with `Labels.Serialize(withQuotes: true)`, so what reaches a
/// provider is `"heritage=external-dns,..."` with the quotes part of the string. Quoting
/// that again stores `"\"heritage=...\""`, and deSEC then serves a TXT value whose data
/// carries two literal quote characters.
///
/// Nothing ever repaired it, because the round trip stays consistent with itself:
/// [`txt_unquote`] takes exactly one layer back off, so external-dns compares equal and
/// never asks for a rewrite. Only the zone is wrong, and only to whoever reads it.
///
/// Recognized by the heritage marker rather than by being quoted at all. Quotes around a
/// target external-dns did not serialize are data, and unwrapping them would report back
/// something other than what the source asked for — which is a write every cycle.
fn strip_external_dns_quoting(target: &str) -> Option<&str> {
    let inner = target.strip_prefix('"')?.strip_suffix('"')?;
    // Serialize wraps and does nothing else, so a quote or a backslash left inside is
    // not its doing, whatever the value starts with.
    let unescaped = !inner.contains('"') && !inner.contains('\\');
    (inner.starts_with(OWNERSHIP_PREFIX) && unescaped).then_some(inner)
}

/// external-dns's plain value to deSEC's TXT presentation form.
///
/// One quoted chunk, however long the value. deSEC splits anything over 255 bytes itself,
/// and letting it do so is what keeps our idea of the split from ever disagreeing with
/// its own — a disagreement that would make the value compare unequal forever.
pub fn txt_quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for character in raw.chars() {
        if character == '"' || character == '\\' {
            out.push('\\');
        }
        out.push(character);
    }
    out.push('"');
    out
}

/// The subname an FQDN has within a zone.
///
/// `None` when the name is not inside the zone at all, which the caller reports rather
/// than guessing at.
pub fn subname_within(fqdn: &str, zone: &str) -> Option<Subname> {
    let fqdn = canonical_name(fqdn);
    let zone = canonical_name(zone);

    if fqdn == zone {
        return Some(Subname::apex());
    }
    let prefix = fqdn.strip_suffix(&format!(".{zone}"))?;
    Subname::new(prefix).ok()
}

/// The FQDN of a subname in a zone, in the dotless form external-dns expects.
pub fn fqdn_of(subname: &Subname, zone: &str) -> String {
    if subname.is_apex() {
        zone.to_owned()
    } else {
        format!("{}.{}", subname.as_payload(), zone)
    }
}

/// Whether an RRset is deSEC's to manage rather than external-dns's.
///
/// Reporting them would be actively harmful. They are not ours to write -- deSEC rejects any
/// attempt -- so every plan that touches one produces a request that can only ever fail. Under
/// `--registry=txt` a delete is filtered out by owner ID, but under `--registry=noop` that
/// filter is skipped entirely and an apex `SOA` or `NS` becomes a delete deSEC rejects, every
/// cycle, forever.
///
/// Scoped to the apex on purpose. `DS` at a *subname* is an ordinary delegation record
/// that an operator may well want external-dns to manage, even though `DS` at the apex
/// belongs to the parent zone.
pub fn is_provider_managed(subname: &Subname, record_type: &RecordType) -> bool {
    if matches!(record_type, RecordType::RRSIG | RecordType::NSEC3PARAM) {
        return true;
    }
    subname.is_apex() && (record_type.is_dnssec_managed() || *record_type == RecordType::NS)
}

/// An RDATA value in the shape external-dns uses: any embedded domain name bare and
/// lowercase.
///
/// Applied to *both* directions of the comparison — to what deSEC returns, and to what
/// external-dns asks for — so that neither side can differ from the other by a trailing
/// dot or a capital letter. Text types are left alone: their external-dns form is the
/// plain value, and quoting is [`txt_quote`]'s business.
pub fn canonical_rdata(record_type: &RecordType, value: &str) -> String {
    if is_text_type(record_type) {
        return value.to_owned();
    }
    map_rdata_name(record_type, value, canonical_name)
}

/// A stored RRset as the endpoint external-dns expects to see.
///
/// Takes the parts rather than an [`Rrset`] because that is what the snapshot holds, and
/// because `Rrset` is `#[non_exhaustive]` with no constructor — it can only be deserialized
/// from a response, which is the wrong shape for a cache.
pub fn endpoint_from_parts(
    zone: &str,
    subname: &Subname,
    record_type: &RecordType,
    records: &[String],
    ttl: u32,
) -> Endpoint {
    let targets = records
        .iter()
        .map(|record| {
            if is_text_type(record_type) {
                txt_unquote(record)
            } else {
                canonical_rdata(record_type, record)
            }
        })
        .collect();

    Endpoint {
        dns_name: fqdn_of(subname, zone),
        targets,
        record_type: RecordTypeName::new(record_type.as_str()),
        record_ttl: Ttl(i64::from(ttl)),
        ..Endpoint::default()
    }
}

/// The same, straight off the wire.
pub fn endpoint_from_rrset(zone: &str, rrset: &Rrset) -> Endpoint {
    endpoint_from_parts(
        zone,
        &rrset.subname,
        &rrset.record_type,
        &rrset.records,
        rrset.ttl,
    )
}

/// An endpoint's targets as deSEC's `records` array.
pub fn records_for(record_type: &RecordType, targets: &[String]) -> Vec<String> {
    targets
        .iter()
        .map(|target| {
            if is_text_type(record_type) {
                // external-dns's own quoting comes off before deSEC's goes on, or the
                // value reaches the zone wrapped twice.
                txt_quote(strip_external_dns_quoting(target).unwrap_or(target))
            } else {
                map_rdata_name(record_type, target, |name| {
                    let bare = canonical_name(name);
                    // The root is a bare dot, which trim_end_matches leaves empty.
                    if bare.is_empty() {
                        ".".to_owned()
                    } else {
                        format!("{bare}.")
                    }
                })
            }
        })
        .collect()
}

/// The record type an endpoint names, or `None` if deSEC could not accept it.
pub fn record_type_of(name: &RecordTypeName) -> Option<RecordType> {
    name.as_str().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rrset(subname: &str, record_type: RecordType, ttl: u32, records: &[&str]) -> Rrset {
        // Rrset is #[non_exhaustive] and read-only in the API, so build it the way the
        // client does: from the JSON deSEC sends.
        serde_json::from_value(serde_json::json!({
            "domain": "example.com",
            "subname": subname,
            "type": record_type.as_str(),
            "name": if subname.is_empty() { "example.com.".to_owned() } else { format!("{subname}.example.com.") },
            "records": records,
            "ttl": ttl,
            "created": "2026-01-01T00:00:00Z",
            "touched": "2026-01-01T00:00:00Z",
        }))
        .expect("valid rrset json")
    }

    #[test]
    fn canonical_names_are_dotless_and_lowercase() {
        for (raw, expected) in [
            ("Foo.Example.COM.", "foo.example.com"),
            ("foo.example.com", "foo.example.com"),
            ("  example.com.  ", "example.com"),
        ] {
            assert_eq!(canonical_name(raw), expected);
        }
    }

    /// The regression this pins is a write loop, not a cosmetic difference: a dotted
    /// `dnsName` makes the TXT registry force-update every record on every reconcile.
    #[test]
    fn reported_dns_names_never_carry_a_trailing_dot() {
        for subname in ["", "www", "deep.nested.thing", "*"] {
            let endpoint = endpoint_from_rrset(
                "example.com",
                &rrset(subname, RecordType::A, 3600, ["1.2.3.4"].as_slice()),
            );
            assert!(
                !endpoint.dns_name.ends_with('.'),
                "{:?} ends with a dot",
                endpoint.dns_name
            );
        }
    }

    #[test]
    fn the_apex_is_the_zone_itself_in_both_directions() {
        let endpoint = endpoint_from_rrset(
            "example.com",
            &rrset("", RecordType::A, 3600, ["1.2.3.4"].as_slice()),
        );
        assert_eq!(endpoint.dns_name, "example.com");

        let subname = subname_within("example.com", "example.com").expect("in zone");
        assert!(subname.is_apex());
        // deSEC spells the apex "" in a payload and "@" in a path; both must survive.
        assert_eq!(subname.as_payload(), "");
        assert_eq!(subname.as_path(), "@");
    }

    #[test]
    fn a_name_outside_the_zone_has_no_subname() {
        // The shape the default --txt-prefix produces for an apex endpoint: a sibling of
        // the zone, not a child of it.
        assert!(subname_within("externaldns-a-example.com", "example.com").is_none());
        assert!(subname_within("notexample.com", "example.com").is_none());
    }

    #[test]
    fn the_rdata_name_field_is_the_only_field_that_gains_a_dot() {
        for (record_type, target, wire) in [
            (RecordType::CNAME, "alias.example.org", "alias.example.org."),
            (
                RecordType::MX,
                "10 mail.example.org",
                "10 mail.example.org.",
            ),
            (
                RecordType::SRV,
                "10 20 443 host.example.org",
                "10 20 443 host.example.org.",
            ),
            (
                RecordType::NAPTR,
                r#"100 10 "s" "http" "" host.example.org"#,
                r#"100 10 "s" "http" "" host.example.org."#,
            ),
            (RecordType::HTTPS, "1 svc.example.org", "1 svc.example.org."),
            // No name field: untouched, dots and all.
            (RecordType::A, "192.0.2.1", "192.0.2.1"),
            (
                RecordType::CAA,
                "0 issue \"letsencrypt.org\"",
                "0 issue \"letsencrypt.org\"",
            ),
        ] {
            assert_eq!(
                records_for(&record_type, &[target.to_owned()]),
                vec![wire.to_owned()],
                "{record_type:?} ingress"
            );
            let round_tripped = endpoint_from_rrset(
                "example.com",
                &rrset("x", record_type.clone(), 3600, [wire].as_slice()),
            );
            assert_eq!(
                round_tripped.targets,
                vec![target.to_owned()],
                "{record_type:?} egress"
            );
        }
    }

    #[test]
    fn an_already_qualified_target_does_not_gain_a_second_dot() {
        assert_eq!(
            records_for(&RecordType::CNAME, &["alias.example.org.".to_owned()]),
            vec!["alias.example.org.".to_owned()]
        );
    }

    #[test]
    fn a_target_malformed_for_its_type_passes_through() {
        // Fewer fields than the name index. deSEC stored it, so deSEC accepts it back.
        assert_eq!(
            records_for(&RecordType::SRV, &["10 20".to_owned()]),
            vec!["10 20".to_owned()]
        );
    }

    #[test]
    fn txt_quotes_come_off_on_the_way_out_and_back_on_the_way_in() {
        let heritage = "heritage=external-dns,external-dns/owner=default";
        let stored = format!("\"{heritage}\"");

        assert_eq!(txt_unquote(&stored), heritage);
        assert_eq!(txt_quote(heritage), stored);
    }

    /// A value over 255 bytes comes back from deSEC as several chunks. Joining them is
    /// what makes the ownership TXT compare equal; treating them as separate targets is
    /// what made the previous provider churn.
    #[test]
    fn multi_chunk_txt_is_one_target_not_several() {
        assert_eq!(txt_unquote(r#""part-one" "part-two""#), "part-onepart-two");

        let long = "x".repeat(300);
        let endpoint = endpoint_from_rrset(
            "example.com",
            &rrset(
                "x",
                RecordType::TXT,
                3600,
                [format!("\"{}\" \"{}\"", &long[..255], &long[255..]).as_str()].as_slice(),
            ),
        );
        assert_eq!(endpoint.targets, vec![long]);
    }

    #[test]
    fn txt_escapes_survive_a_round_trip() {
        for raw in [
            r#"has "quotes" inside"#,
            r"has \backslash inside",
            "",
            "v=DMARC1; p=none; rua=mailto:a@example.com",
            "trailing backslash \\",
        ] {
            assert_eq!(txt_unquote(&txt_quote(raw)), raw, "{raw:?}");
        }
    }

    #[test]
    fn txt_decodes_decimal_octet_escapes() {
        // \013 is a carriage return, which deSEC documents as the way to carry one.
        assert_eq!(txt_unquote(r#""a\013b""#), "a\rb");
        // A backslash before something that is not three digits is a literal escape.
        assert_eq!(txt_unquote(r#""a\1b""#), "a1b");
    }

    #[test]
    fn an_unquoted_legacy_txt_value_passes_through() {
        assert_eq!(
            txt_unquote("heritage=external-dns"),
            "heritage=external-dns"
        );
    }

    /// What external-dns actually sends. The registry serializes ownership values with
    /// the quotes already on, so quoting again put `"\"heritage=...\""` in the zone.
    #[test]
    fn an_ownership_value_external_dns_quoted_is_not_quoted_a_second_time() {
        let serialized = r#""heritage=external-dns,external-dns/owner=k8s,external-dns/resource=httproute/ns/name""#;

        assert_eq!(
            records_for(&RecordType::TXT, &[serialized.to_owned()]),
            vec![serialized.to_owned()]
        );
    }

    /// And quotes around anything else stay data: they are escaped and wrapped like any
    /// other byte, because reporting back less than the source asked for is a write loop.
    #[test]
    fn quotes_around_a_value_of_no_heritage_are_content() {
        assert_eq!(
            records_for(&RecordType::TXT, &[r#""v=spf1 -all""#.to_owned()]),
            vec![r#""\"v=spf1 -all\"""#.to_owned()]
        );
    }

    #[test]
    fn spf_records_are_quoted_like_txt() {
        assert_eq!(
            records_for(&RecordType::SPF, &["v=spf1 -all".to_owned()]),
            vec![r#""v=spf1 -all""#.to_owned()]
        );
    }

    /// The regression pin against a closed record-type enum, which is a shipped bug in
    /// the `externaldns-webhook` crate on crates.io.
    #[test]
    fn every_type_external_dns_can_emit_converts() {
        for mnemonic in [
            "A", "AAAA", "CNAME", "TXT", "SRV", "NS", "PTR", "MX", "NAPTR", "CAA", "DS", "TLSA",
            "HTTPS", "SVCB", "SPF", "SSHFP", "URI", "LOC",
        ] {
            assert!(
                record_type_of(&RecordTypeName::new(mnemonic)).is_some(),
                "{mnemonic} did not convert"
            );
        }
    }

    #[test]
    fn a_type_this_build_has_never_heard_of_still_converts() {
        assert_eq!(
            record_type_of(&RecordTypeName::new("WALLET")),
            Some(RecordType::Other("WALLET".to_owned()))
        );
    }

    #[test]
    fn desec_managed_records_are_hidden_only_where_desec_owns_them() {
        let apex = Subname::apex();
        let sub = Subname::new("delegated").expect("valid");

        // Apex: deSEC's.
        for record_type in [
            RecordType::SOA,
            RecordType::DNSKEY,
            RecordType::NS,
            RecordType::DS,
        ] {
            assert!(is_provider_managed(&apex, &record_type), "{record_type:?}");
        }
        // Subname: an ordinary delegation the operator may manage.
        for record_type in [RecordType::NS, RecordType::DS, RecordType::A] {
            assert!(!is_provider_managed(&sub, &record_type), "{record_type:?}");
        }
        // Never ours, at any name.
        assert!(is_provider_managed(&sub, &RecordType::RRSIG));
    }

    proptest! {
        /// The property that retires the TXT quoting bug for good: whatever external-dns
        /// hands us survives storage in deSEC's presentation format.
        #[test]
        fn txt_round_trips_for_any_value(raw in ".{0,400}") {
            prop_assert_eq!(txt_unquote(&txt_quote(&raw)), raw);
        }

        /// And the same for a name: canonicalization is a fixpoint, so a value that has
        /// been through it once cannot drift by going through it again.
        #[test]
        fn canonicalization_is_idempotent(raw in "[a-zA-Z0-9.-]{0,60}") {
            let once = canonical_name(&raw);
            prop_assert_eq!(canonical_name(&once), once.clone());
        }
    }
}
