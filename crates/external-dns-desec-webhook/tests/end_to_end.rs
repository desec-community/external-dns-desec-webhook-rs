//! The webhook driven over a real socket, against a stateful stand-in for deSEC.
//!
//! Every test here is named for the protocol fact or the historical bug it pins.

#![allow(clippy::unwrap_used)]

mod common;

use common::Harness;
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::json;

const MEDIA_TYPE: &str = "application/external.dns.webhook+json;version=1";

/// external-dns compares this header with Go `==`, so a normalising writer that emits
/// `; version=1` fails the handshake — and the handshake runs once at startup and is fatal.
#[tokio::test]
async fn the_negotiate_content_type_is_byte_exact() {
    let harness = Harness::start(&["example.com"]).await;

    let response = Harness::client()
        .get(&harness.base)
        .headers(Harness::accept())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let header = response.headers().get(CONTENT_TYPE).unwrap();
    assert_eq!(header.as_bytes(), MEDIA_TYPE.as_bytes());
    assert!(
        !header.as_bytes().contains(&b' '),
        "a single inserted space breaks the handshake"
    );
    assert_eq!(
        response.headers().get_all(CONTENT_TYPE).iter().count(),
        1,
        "a duplicate header would be appended, not replaced"
    );
}

/// The published `api/webhook.yaml` documents `{"filters": [...]}`. That key does not exist in
/// `endpoint.domainFilterSerde`, so emitting it negotiates an *empty* filter, which
/// external-dns reads as "every domain".
#[tokio::test]
async fn the_negotiate_body_uses_include_not_filters() {
    let harness = Harness::start(&["example.com"]).await;

    let body: serde_json::Value = Harness::client()
        .get(&harness.base)
        .headers(Harness::accept())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(body, json!({"include": ["example.com"]}));
    assert!(body.get("filters").is_none());
}

/// The Magicloud crate's actix route guard answers 404 when `Accept` is absent, and a 404 is
/// permanent to external-dns. Nothing here is ever routed on `Accept`.
#[tokio::test]
async fn negotiation_succeeds_whatever_accept_says() {
    let harness = Harness::start(&["example.com"]).await;

    for accept in [
        None,
        Some("*/*"),
        Some("application/json"),
        Some(MEDIA_TYPE),
    ] {
        let mut request = Harness::client().get(&harness.base);
        if let Some(accept) = accept {
            request = request.header(ACCEPT, accept);
        }
        assert_eq!(
            request.send().await.unwrap().status(),
            StatusCode::OK,
            "Accept: {accept:?}"
        );
    }
}

/// The dotted form is what made the TXT registry set `txt/force-update` on every record on
/// every cycle, which `plan.providerSpecificChanged()` then promoted into an update.
#[tokio::test]
async fn records_are_reported_without_a_trailing_dot() {
    let harness = Harness::start(&["example.com"]).await;
    harness
        .mock
        .seed("example.com", "www", "A", &["192.0.2.1"], 3600);
    // The apex, whose name is the zone itself.
    harness
        .mock
        .seed("example.com", "", "A", &["192.0.2.2"], 3600);
    harness.mock.seed(
        "example.com",
        "alias",
        "CNAME",
        &["target.example.org."],
        3600,
    );
    harness.reload().await;

    let body = records(&harness).await;

    let mut names: Vec<&str> = body
        .iter()
        .map(|endpoint| endpoint["dnsName"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["alias.example.com", "example.com", "www.example.com"]
    );

    // And the same inside RDATA, where the dot rides on one field rather than the value.
    let alias = body
        .iter()
        .find(|endpoint| endpoint["recordType"] == "CNAME")
        .unwrap();
    assert_eq!(alias["targets"], json!(["target.example.org"]));
}

/// An empty array is not "nothing to do", it is a claim the zone is empty, and external-dns
/// plans a Create for every endpoint it knows about. A 503 is retried; a claim is believed.
#[tokio::test]
async fn records_answers_503_rather_than_an_empty_array_when_no_zone_is_managed() {
    // A configured zone the account does not hold.
    let harness = Harness::start(&[]).await;

    let response = Harness::client()
        .get(format!("{}/records", harness.base))
        .headers(Harness::accept())
        .send()
        .await
        .unwrap();

    let status = response.status().as_u16();
    assert!(
        (500..=510).contains(&status),
        "{status} is not a status external-dns retries"
    );
    assert!(
        !response.text().await.unwrap().is_empty(),
        "an error body is what lets the client pool the connection"
    );
}

/// `axum::Json` as an extractor would answer 415 here, because external-dns sends the webhook
/// media type rather than `application/json` — making every write a permanent failure.
#[tokio::test]
async fn apply_accepts_the_webhook_content_type_and_answers_exactly_204() {
    let harness = Harness::start(&["example.com"]).await;

    let response = Harness::client()
        .post(format!("{}/records", harness.base))
        .header(CONTENT_TYPE, MEDIA_TYPE)
        .body(
            json!({
                "create": [{
                    "dnsName": "www.example.com",
                    "recordType": "A",
                    "recordTTL": 3600,
                    "targets": ["192.0.2.1"],
                }]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.text().await.unwrap().is_empty(), "204 has no body");
    assert_eq!(
        harness.mock.state("example.com").get("www/A"),
        Some(&vec!["192.0.2.1".to_owned()])
    );
}

/// external-dns sends no `Accept` at all on ApplyChanges, which alone rules out routing on it.
#[tokio::test]
async fn apply_succeeds_with_no_accept_header() {
    let harness = Harness::start(&["example.com"]).await;

    let response = Harness::client()
        .post(format!("{}/records", harness.base))
        .header(CONTENT_TYPE, MEDIA_TYPE)
        .body(json!({}).to_string())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

/// Go's `omitempty` means any field may be absent, and a nil slice marshals as `null`.
#[tokio::test]
async fn apply_accepts_absent_and_null_change_fields() {
    let harness = Harness::start(&["example.com"]).await;

    for body in [
        json!({}),
        json!({"create": null, "updateOld": null, "updateNew": null, "delete": null}),
        json!({"create": []}),
    ] {
        let response = Harness::client()
            .post(format!("{}/records", harness.base))
            .header(CONTENT_TYPE, MEDIA_TYPE)
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{body}");
    }
    assert_eq!(
        harness.mock.mutations(),
        0,
        "nothing to do, nothing written"
    );
}

/// The wedge this design exists to prevent. As two requests in either order deSEC rejects one
/// of them and the zone never converges; as one atomic request it validates the final state.
#[tokio::test]
async fn a_record_type_change_succeeds_as_a_single_request() {
    let harness = Harness::start(&["example.com"]).await;

    // Establish the A record through the webhook, so the snapshot knows about it.
    apply(
        &harness,
        json!({"create": [endpoint("www.example.com", "A", ["192.0.2.1"])]}),
    )
    .await;
    let after_create = harness.mock.mutations();

    // Now retype it: external-dns sends this as a delete plus a create.
    let status = apply(
        &harness,
        json!({
            "create": [endpoint("www.example.com", "CNAME", ["target.example.org"])],
            "delete": [endpoint("www.example.com", "A", ["192.0.2.1"])],
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the retype must be accepted"
    );
    assert_eq!(
        harness.mock.mutations() - after_create,
        1,
        "one atomic request, not two"
    );

    let state = harness.mock.state("example.com");
    assert!(!state.contains_key("www/A"), "the A record is gone");
    assert_eq!(
        state.get("www/CNAME"),
        Some(&vec!["target.example.org.".to_owned()]),
        "and the CNAME is present, fully qualified as deSEC stores it"
    );
}

/// The regression that mattered most: a settled cluster must cost nothing. This is the whole
/// reason the previous provider exhausted a 300-writes-a-day budget on an idle zone.
#[tokio::test]
async fn re_applying_the_same_change_makes_no_second_request() {
    let harness = Harness::start(&["example.com"]).await;
    let change = json!({"create": [endpoint("www.example.com", "A", ["192.0.2.1"])]});

    assert_eq!(
        apply(&harness, change.clone()).await,
        StatusCode::NO_CONTENT
    );
    let after_first = harness.mock.mutations();
    assert_eq!(after_first, 1);

    // Ten more cycles asking for exactly what is already stored.
    for _ in 0..10 {
        assert_eq!(
            apply(&harness, change.clone()).await,
            StatusCode::NO_CONTENT
        );
    }

    assert_eq!(
        harness.mock.mutations(),
        after_first,
        "a settled cluster must not spend quota"
    );
}

/// TTL is clamped against the zone's own minimum, and an ownership record arrives with none at
/// all: the TXT registry builds them with `endpoint.NewEndpoint` — TTL 0 — inside ApplyChanges,
/// after `/adjustendpoints` has already run.
#[tokio::test]
async fn an_ownership_record_arriving_without_a_ttl_is_stored_with_the_zone_minimum() {
    let harness = Harness::start(&["example.com"]).await;

    apply(
        &harness,
        json!({"create": [{
            "dnsName": "externaldns-a.www.example.com",
            "recordType": "TXT",
            "targets": ["heritage=external-dns,external-dns/owner=lab"],
        }]}),
    )
    .await;

    let state = harness.mock.state("example.com");
    let stored = state.get("externaldns-a.www/TXT").unwrap();
    // Quoted the way deSEC stores character-strings, which is what makes the value round-trip
    // and stops the ownership record churning.
    assert_eq!(
        stored,
        &vec![r#""heritage=external-dns,external-dns/owner=lab""#.to_owned()]
    );
}

/// With the default `--txt-prefix`, the companion record for a zone apex is named in the
/// *parent* zone. deSEC scopes every call to a zone we own, so it cannot be created. Skipping
/// it keeps the rest of the cycle applying instead of failing the batch.
#[tokio::test]
async fn a_change_outside_every_managed_zone_is_skipped_not_failed() {
    let harness = Harness::start(&["example.com"]).await;

    let status = apply(
        &harness,
        json!({"create": [
            endpoint("externaldns-a-example.com", "TXT", ["heritage=external-dns"]),
            endpoint("ok.example.com", "A", ["192.0.2.1"]),
        ]}),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(harness.mock.state("example.com").contains_key("ok/A"));
}

#[tokio::test]
async fn adjust_endpoints_clamps_ttl_and_leaves_everything_else_alone() {
    let harness = Harness::start(&["example.com"]).await;

    let body: Vec<serde_json::Value> = Harness::client()
        .post(format!("{}/adjustendpoints", harness.base))
        .header(CONTENT_TYPE, MEDIA_TYPE)
        .headers(Harness::accept())
        .body(
            json!([{
                "dnsName": "www.example.com",
                "recordType": "A",
                "recordTTL": 0,
                "targets": ["192.0.2.1"],
                "setIdentifier": "weighted-1",
                "labels": {"owner": "lab"},
                "providerSpecific": [{"name": "a", "value": "1"}, {"name": "a", "value": "2"}],
            }])
            .to_string(),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(body.len(), 1);
    // The fix for the write loop: external-dns now compares 3600 against 3600.
    assert_eq!(body[0]["recordTTL"], json!(3600));
    // Everything the plan compares has to come back untouched, duplicates included.
    assert_eq!(body[0]["setIdentifier"], json!("weighted-1"));
    assert_eq!(body[0]["labels"], json!({"owner": "lab"}));
    assert_eq!(
        body[0]["providerSpecific"],
        json!([{"name": "a", "value": "1"}, {"name": "a", "value": "2"}])
    );
}

/// deSEC signs and serves these itself. Reporting them would have external-dns plan a delete
/// for the apex SOA and NS on every cycle, and deSEC would reject every one.
#[tokio::test]
async fn records_desec_manages_itself_are_not_reported() {
    let harness = Harness::start(&["example.com"]).await;
    harness.mock.seed(
        "example.com",
        "",
        "NS",
        &["ns1.desec.io.", "ns2.desec.org."],
        3600,
    );
    harness
        .mock
        .seed("example.com", "", "SOA", &["ns1.desec.io. ..."], 3600);
    harness
        .mock
        .seed("example.com", "www", "A", &["192.0.2.1"], 3600);

    harness.reload().await;

    let body = records(&harness).await;
    let types: Vec<&str> = body
        .iter()
        .map(|endpoint| endpoint["recordType"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"A"), "{types:?}");
    assert!(!types.contains(&"NS"), "apex NS is deSEC's: {types:?}");
    assert!(!types.contains(&"SOA"), "{types:?}");
}

#[tokio::test]
async fn an_unroutable_path_does_not_panic() {
    let harness = Harness::start(&["example.com"]).await;

    for (method, path) in [("GET", "/nonsense"), ("DELETE", "/records")] {
        let request =
            Harness::client().request(method.parse().unwrap(), format!("{}{path}", harness.base));
        let status = request.send().await.unwrap().status();
        // 404/405 is correct: external-dns only ever calls the four documented routes.
        assert!(status.is_client_error(), "{method} {path} gave {status}");
    }
}

// -- helpers --------------------------------------------------------------------------------

fn endpoint(dns_name: &str, record_type: &str, targets: [&str; 1]) -> serde_json::Value {
    json!({
        "dnsName": dns_name,
        "recordType": record_type,
        "recordTTL": 3600,
        "targets": targets,
    })
}

async fn apply(harness: &Harness, body: serde_json::Value) -> StatusCode {
    Harness::client()
        .post(format!("{}/records", harness.base))
        .header(CONTENT_TYPE, MEDIA_TYPE)
        .body(body.to_string())
        .send()
        .await
        .unwrap()
        .status()
}

async fn records(harness: &Harness) -> Vec<serde_json::Value> {
    Harness::client()
        .get(format!("{}/records", harness.base))
        .headers(Harness::accept())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}
