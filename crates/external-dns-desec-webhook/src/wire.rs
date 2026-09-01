//! The external-dns webhook wire format.
//!
//! Every type here mirrors a Go type in external-dns, and the mapping was established by
//! reading `endpoint/endpoint.go`, `endpoint/domain_filter.go`, `plan/plan.go` and
//! `provider/webhook/webhook.go` at v0.21.0; the doctests below are what keep them true.
//!
//! Nothing in this module knows about deSEC, and nothing in it is async.

use std::collections::BTreeMap;

use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Deserializer, Serialize};

/// The vendored media type external-dns negotiates with.
///
/// Note the absence of a space after the semicolon. external-dns compares the negotiate
/// response's `Content-Type` against this string with Go `==`, so a normalising header
/// writer that emits `; version=1` fails the handshake — and the handshake runs once at
/// startup and is fatal.
pub const MEDIA_TYPE: &str = "application/external.dns.webhook+json;version=1";

/// `MEDIA_TYPE` as a header value, built at compile time so a bad byte cannot reach
/// runtime.
pub const MEDIA_TYPE_HEADER: HeaderValue = HeaderValue::from_static(MEDIA_TYPE);

/// A JSON response body carrying [`MEDIA_TYPE`] byte-exactly.
///
/// Deliberately not `axum::Json` and deliberately not `mime`: both normalise media-type
/// parameters to `"; version=1"`, which external-dns rejects.
///
/// ```
/// use axum::response::IntoResponse;
/// use external_dns_desec_webhook::wire::{MEDIA_TYPE, WebhookJson};
///
/// let response = WebhookJson(vec![1, 2, 3]).into_response();
/// let content_type = response.headers().get("content-type").unwrap();
///
/// assert_eq!(content_type.as_bytes(), MEDIA_TYPE.as_bytes());
/// assert!(!content_type.as_bytes().contains(&b' '));
/// // Exactly one, so nothing downstream can have appended a second.
/// assert_eq!(response.headers().get_all("content-type").iter().count(), 1);
/// ```
#[derive(Debug)]
pub struct WebhookJson<T>(pub T);

impl<T: Serialize> IntoResponse for WebhookJson<T> {
    fn into_response(self) -> Response {
        match serde_json::to_vec(&self.0) {
            Ok(body) => ([(header::CONTENT_TYPE, MEDIA_TYPE_HEADER)], body).into_response(),
            Err(error) => crate::error::WebhookError::Encode(error).into_response(),
        }
    }
}

/// Deserialize a field that may be absent *or* explicitly `null`.
///
/// `#[serde(default)]` covers only the absent case; `"targets": null` still fails with
/// "invalid type: null". Go emits `null` for a nil slice or map, and every field of
/// external-dns's `Endpoint` is `omitempty`, so both spellings arrive in practice.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// A DNS record type mnemonic, as external-dns spells it.
///
/// A `String` newtype rather than [`desec::RecordType`], because this value is
/// round-tripped through `/adjustendpoints` untouched and a mnemonic we cannot name must
/// not become a deserialization failure: axum would answer `400`, and external-dns treats
/// every 4xx as permanent, so one odd endpoint would wedge the whole reconcile loop.
/// Validation happens in `convert`, where the blast radius is one skipped endpoint.
///
/// ```
/// use external_dns_desec_webhook::wire::RecordTypeName;
///
/// let caa: RecordTypeName = serde_json::from_str(r#""CAA""#).unwrap();
/// assert!(caa.is("caa")); // comparison is case-insensitive
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecordTypeName(String);

impl RecordTypeName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Case-insensitive comparison against a mnemonic, so the check lives in one place
    /// rather than being spelled `== "TXT"` at each call site.
    pub fn is(&self, mnemonic: &str) -> bool {
        self.0.eq_ignore_ascii_case(mnemonic)
    }
}

/// A record TTL in seconds.
///
/// Signed, matching Go's `endpoint.TTL = int64`. A `u32` would turn a negative TTL from a
/// buggy source into a deserialization failure, and therefore into a permanent `400`.
/// "Unset" is any non-positive value, matching Go's `IsConfigured`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ttl(pub i64);

impl Ttl {
    pub fn is_unset(&self) -> bool {
        self.0 <= 0
    }
}

/// One provider-specific annotation.
///
/// external-dns serializes `providerSpecific` as an **array** of these, not as a map. A
/// map drops duplicate names and changes the JSON its TXT registry compares against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSpecificProperty {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

/// A DNS record as external-dns models it.
///
/// ```
/// use external_dns_desec_webhook::wire::Endpoint;
///
/// // Every field is `omitempty` in Go, so an endpoint may arrive almost bare...
/// let bare: Endpoint = serde_json::from_str("{}").unwrap();
/// // ...or with explicit nulls where Go marshalled a nil slice or map.
/// let nulled: Endpoint =
///     serde_json::from_str(r#"{"targets":null,"labels":null,"providerSpecific":null}"#).unwrap();
/// assert_eq!(bare, nulled);
///
/// // The TTL key is `recordTTL`, not the `recordTtl` that camelCasing `record_ttl` gives.
/// let ttl: Endpoint = serde_json::from_str(r#"{"recordTTL":3600}"#).unwrap();
/// assert_eq!(ttl.record_ttl.0, 3600);
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
// No `deny_unknown_fields` anywhere in this module: external-dns adds fields to Endpoint
// between minor versions, and rejecting one would be a permanent failure.
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dns_name: String,

    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub targets: Vec<String>,

    #[serde(default, skip_serializing_if = "RecordTypeName::is_empty")]
    pub record_type: RecordTypeName,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub set_identifier: String,

    // `rename_all = "camelCase"` would give `recordTtl`. Spelled out, and pinned by a
    // doctest above, because a silently-never-matching key is exactly the bug that made
    // the `externaldns-webhook` crate deserialize every update as empty.
    #[serde(rename = "recordTTL", default, skip_serializing_if = "Ttl::is_unset")]
    pub record_ttl: Ttl,

    // BTreeMap, not HashMap: deterministic serialization is what makes golden-payload
    // diffs and debug logs readable.
    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub labels: BTreeMap<String, String>,

    #[serde(
        default,
        deserialize_with = "null_as_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub provider_specific: Vec<ProviderSpecificProperty>,
}

/// The plan external-dns wants applied.
///
/// ```
/// use external_dns_desec_webhook::wire::Changes;
///
/// let changes: Changes = serde_json::from_str(
///     r#"{"create":[],"updateOld":[],"updateNew":[{"dnsName":"a.example.com"}],"delete":null}"#,
/// )
/// .unwrap();
/// assert_eq!(changes.update_new.len(), 1);
/// assert!(changes.delete.is_empty());
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Changes {
    #[serde(default, deserialize_with = "null_as_default")]
    pub create: Vec<Endpoint>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub update_old: Vec<Endpoint>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub update_new: Vec<Endpoint>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub delete: Vec<Endpoint>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.create.is_empty()
            && self.update_new.is_empty()
            && self.delete.is_empty()
            && self.update_old.is_empty()
    }
}

/// The zone filter external-dns learns from the negotiate handshake.
///
/// The wire format is whatever `endpoint.DomainFilter.MarshalJSON` produces, which is the
/// include/exclude form or the regex form:
///
/// ```
/// use external_dns_desec_webhook::wire::DomainFilter;
///
/// let filter = DomainFilter::include(["example.com"]);
/// assert_eq!(
///     serde_json::to_string(&filter).unwrap(),
///     r#"{"include":["example.com"]}"#,
/// );
/// ```
///
/// external-dns's own `api/webhook.yaml` documents `{"filters": [...]}` instead. That is
/// outdated and wrong: `filters` is not a key `domainFilterSerde` knows, so a webhook
/// emitting it negotiates an *empty* filter — which external-dns reads as "every domain".
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainFilter {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub regex_include: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub regex_exclude: String,
}

impl DomainFilter {
    pub fn include(zones: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            include: zones.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The literal key strings, all of them, in one place. Every one of these has been a
    /// shipped bug in some webhook implementation.
    #[test]
    fn endpoint_keys_are_spelled_as_external_dns_spells_them() {
        let endpoint = Endpoint {
            dns_name: "a.example.com".into(),
            targets: vec!["192.0.2.1".into()],
            record_type: RecordTypeName::new("A"),
            set_identifier: "v1".into(),
            record_ttl: Ttl(3600),
            labels: BTreeMap::from([("owner".to_owned(), "default".to_owned())]),
            provider_specific: vec![ProviderSpecificProperty {
                name: "foo".into(),
                value: "bar".into(),
            }],
        };

        let json = serde_json::to_string(&endpoint).expect("serializes");
        for key in [
            "\"dnsName\"",
            "\"targets\"",
            "\"recordType\"",
            "\"setIdentifier\"",
            "\"recordTTL\"",
            "\"labels\"",
            "\"providerSpecific\"",
        ] {
            assert!(json.contains(key), "{key} missing from {json}");
        }
    }

    #[test]
    fn changes_keys_are_camel_case_not_pascal_case() {
        let json = serde_json::to_string(&Changes::default()).expect("serializes");
        for key in ["\"create\"", "\"updateOld\"", "\"updateNew\"", "\"delete\""] {
            assert!(json.contains(key), "{key} missing from {json}");
        }
    }

    #[test]
    fn provider_specific_is_an_array_of_objects_not_a_map() {
        let endpoint: Endpoint = serde_json::from_str(
            r#"{"providerSpecific":[{"name":"a","value":"1"},{"name":"a","value":"2"}]}"#,
        )
        .expect("deserializes");

        // Two entries with the same name survive; a map would have kept one.
        assert_eq!(endpoint.provider_specific.len(), 2);
    }

    #[test]
    fn empty_endpoint_serializes_to_an_empty_object() {
        let json = serde_json::to_string(&Endpoint::default()).expect("serializes");
        assert_eq!(json, "{}");
    }

    #[test]
    fn domain_filter_round_trips_all_four_shapes() {
        for (value, json) in [
            (DomainFilter::default(), "{}"),
            (
                DomainFilter::include(["example.com"]),
                r#"{"include":["example.com"]}"#,
            ),
            (
                DomainFilter {
                    exclude: vec!["internal.example.com".into()],
                    ..DomainFilter::default()
                },
                r#"{"exclude":["internal.example.com"]}"#,
            ),
            (
                DomainFilter {
                    regex_include: "^example\\.".into(),
                    regex_exclude: "internal".into(),
                    ..DomainFilter::default()
                },
                r#"{"regexInclude":"^example\\.","regexExclude":"internal"}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&value).expect("serializes"), json);
            assert_eq!(
                serde_json::from_str::<DomainFilter>(json).expect("deserializes"),
                value
            );
        }
    }

    #[test]
    fn domain_filter_never_emits_the_documented_but_wrong_filters_key() {
        let json = serde_json::to_string(&DomainFilter::include(["example.com"])).expect("ok");
        assert!(!json.contains("filters"), "{json}");
    }

    #[test]
    fn unknown_endpoint_fields_are_ignored() {
        let endpoint: Endpoint =
            serde_json::from_str(r#"{"dnsName":"a.example.com","somethingNew":42}"#)
                .expect("a future external-dns field must not be a hard error");
        assert_eq!(endpoint.dns_name, "a.example.com");
    }

    #[test]
    fn a_negative_ttl_deserializes_rather_than_failing() {
        let endpoint: Endpoint = serde_json::from_str(r#"{"recordTTL":-1}"#).expect("deserializes");
        assert!(endpoint.record_ttl.is_unset());
    }

    #[test]
    fn changes_accepts_an_entirely_absent_body_shape() {
        assert!(
            serde_json::from_str::<Changes>("{}")
                .expect("deserializes")
                .is_empty()
        );
    }
}
