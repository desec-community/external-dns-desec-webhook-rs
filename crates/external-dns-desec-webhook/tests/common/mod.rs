//! Harness for the integration tests: a stateful stand-in for deSEC, and a real webhook
//! server on a real socket.

#![allow(clippy::unwrap_used, dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use external_dns_desec_webhook::apply::Applier;
use external_dns_desec_webhook::metrics::Metrics;
use external_dns_desec_webhook::refresh::Refresher;
use external_dns_desec_webhook::router;
use external_dns_desec_webhook::store::SnapshotStore;
use external_dns_desec_webhook::wire::{DomainFilter, MEDIA_TYPE};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers};

pub const TOKEN: &str = "i-T3b1h_OI-H9ab8tRS98stGtURe";

/// One RRset, keyed the way deSEC keys them.
type Key = (String, String);
type Value = (Vec<String>, u32);

/// An in-memory deSEC, enforcing the two rules that the atomic-bulk design depends on.
///
/// Ported from the Go provider's `desecMock`, and stateful for the same reason it was: both
/// rules are about zone *state* rather than about individual requests. A matcher-based mock
/// can assert "we sent this JSON", which passes even when the plan is semantically wrong —
/// and the A-to-CNAME retype bug was one where the request looked perfectly fine.
pub struct DesecMock {
    zones: Arc<Mutex<BTreeMap<String, BTreeMap<Key, Value>>>>,
    /// Bumped on every accepted mutation, and reported as each zone's `touched` so the
    /// refresher's change detection has something real to react to.
    version: Arc<AtomicUsize>,
    pub mutations: Arc<AtomicUsize>,
    pub rrset_lists: Arc<AtomicUsize>,
    pub zone_lists: Arc<AtomicUsize>,
}

impl DesecMock {
    pub fn new(zones: &[&str]) -> Self {
        Self {
            zones: Arc::new(Mutex::new(
                zones
                    .iter()
                    .map(|zone| ((*zone).to_owned(), BTreeMap::new()))
                    .collect(),
            )),
            version: Arc::new(AtomicUsize::new(0)),
            mutations: Arc::new(AtomicUsize::new(0)),
            rrset_lists: Arc::new(AtomicUsize::new(0)),
            zone_lists: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn handle(&self) -> Self {
        Self {
            zones: Arc::clone(&self.zones),
            version: Arc::clone(&self.version),
            mutations: Arc::clone(&self.mutations),
            rrset_lists: Arc::clone(&self.rrset_lists),
            zone_lists: Arc::clone(&self.zone_lists),
        }
    }

    pub fn seed(&self, zone: &str, subname: &str, record_type: &str, records: &[&str], ttl: u32) {
        let mut zones = self.zones.lock().unwrap();
        let entry = zones.entry(zone.to_owned()).or_default();
        entry.insert(
            (subname.to_owned(), record_type.to_owned()),
            (records.iter().map(|r| (*r).to_owned()).collect(), ttl),
        );
        self.version.fetch_add(1, Ordering::SeqCst);
    }

    /// The zone's contents, as `subname/TYPE -> records`, for assertions.
    pub fn state(&self, zone: &str) -> BTreeMap<String, Vec<String>> {
        self.zones
            .lock()
            .unwrap()
            .get(zone)
            .map(|rrsets| {
                rrsets
                    .iter()
                    .map(|((subname, record_type), (records, _))| {
                        (format!("{subname}/{record_type}"), records.clone())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn mutations(&self) -> usize {
        self.mutations.load(Ordering::SeqCst)
    }

    /// Mount every route this mock answers on a wiremock server.
    pub async fn mount(&self, server: &MockServer) {
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/api/v1/domains/"))
            .respond_with(ZoneList(self.handle()))
            .mount(server)
            .await;

        Mock::given(matchers::path_regex(r"^/api/v1/domains/[^/]+/rrsets/$"))
            .respond_with(Rrsets(self.handle()))
            .mount(server)
            .await;
    }

    fn touched(&self) -> String {
        // A distinct timestamp per version, so `Domain.touched` moving is what the refresher
        // sees rather than a coincidence of wall-clock granularity.
        let version = self.version.load(Ordering::SeqCst);
        format!("2026-01-01T00:{:02}:{:02}Z", version / 60, version % 60)
    }
}

struct ZoneList(DesecMock);

impl Respond for ZoneList {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        self.0.zone_lists.fetch_add(1, Ordering::SeqCst);
        let touched = self.0.touched();
        let body: Vec<serde_json::Value> = self
            .0
            .zones
            .lock()
            .unwrap()
            .keys()
            .map(|name| {
                serde_json::json!({
                    "name": name,
                    "created": "2026-01-01T00:00:00Z",
                    "published": touched,
                    "touched": touched,
                    "minimum_ttl": 3600,
                    "keys": [],
                })
            })
            .collect();
        ResponseTemplate::new(200).set_body_json(body)
    }
}

struct Rrsets(DesecMock);

impl Respond for Rrsets {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let zone = request
            .url
            .path()
            .trim_start_matches("/api/v1/domains/")
            .trim_end_matches("/rrsets/")
            .to_owned();

        match request.method.as_str() {
            "GET" => self.list(&zone),
            "PATCH" => self.bulk(&zone, request, false),
            "POST" => self.bulk(&zone, request, true),
            _ => ResponseTemplate::new(405),
        }
    }
}

impl Rrsets {
    fn list(&self, zone: &str) -> ResponseTemplate {
        self.0.rrset_lists.fetch_add(1, Ordering::SeqCst);
        let zones = self.0.zones.lock().unwrap();
        let Some(rrsets) = zones.get(zone) else {
            return not_found();
        };
        let body: Vec<serde_json::Value> = rrsets
            .iter()
            .map(|((subname, record_type), (records, ttl))| {
                rrset_json(zone, subname, record_type, records, *ttl)
            })
            .collect();
        ResponseTemplate::new(200).set_body_json(body)
    }

    /// Bulk create or patch, atomically.
    ///
    /// The whole request is applied to a clone, the resulting state is validated, and the
    /// clone is committed only if it passes — which is what deSEC documents and what lets a
    /// retype succeed as one request while failing as two.
    fn bulk(&self, zone: &str, request: &Request, create_only: bool) -> ResponseTemplate {
        let Ok(items) = serde_json::from_slice::<Vec<serde_json::Value>>(&request.body) else {
            return ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({"detail": "invalid body"}));
        };

        let mut zones = self.0.zones.lock().unwrap();
        let Some(current) = zones.get(zone) else {
            return not_found();
        };
        let mut next = current.clone();
        let mut errors: Vec<serde_json::Value> = Vec::new();
        let mut touched_keys = Vec::new();
        let mut failed = false;

        for item in &items {
            let subname = item
                .get("subname")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_owned();
            let record_type = item
                .get("type")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned();
            let records: Vec<String> = item
                .get("records")
                .and_then(|value| value.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let ttl = item
                .get("ttl")
                .and_then(serde_json::Value::as_u64)
                .and_then(|ttl| u32::try_from(ttl).ok())
                .unwrap_or(3600);

            let key = (subname.clone(), record_type.clone());

            // deSEC requires `subname` to be present even at the apex, where it must be "".
            // A library that tagged it `omitempty` is why the previous provider could not
            // create apex records at all.
            if item.get("subname").is_none() {
                errors.push(serde_json::json!({"subname": ["This field is required."]}));
                failed = true;
                continue;
            }

            if create_only && current.contains_key(&key) {
                errors.push(serde_json::json!({
                    "non_field_errors": ["Another RRset with the same subdomain and type exists for this domain."]
                }));
                failed = true;
                continue;
            }

            if records.is_empty() {
                next.remove(&key);
            } else {
                next.insert(key.clone(), (records, ttl));
            }
            touched_keys.push(key);
            errors.push(serde_json::json!({}));
        }

        if failed {
            return ResponseTemplate::new(400).set_body_json(errors);
        }
        if let Err(detail) = validate(&next) {
            return ResponseTemplate::new(400)
                .set_body_json(serde_json::json!([{"non_field_errors": [detail]}]));
        }

        self.0.mutations.fetch_add(1, Ordering::SeqCst);
        self.0.version.fetch_add(1, Ordering::SeqCst);

        // Echo the resulting RRsets, including deletions as empty record lists — one of the
        // two response shapes the snapshot update has to cope with.
        let body: Vec<serde_json::Value> = touched_keys
            .iter()
            .map(|key @ (subname, record_type)| {
                let (records, ttl) = next.get(key).cloned().unwrap_or_else(|| (Vec::new(), 3600));
                rrset_json(zone, subname, record_type, &records, ttl)
            })
            .collect();

        *zones.get_mut(zone).unwrap() = next;
        ResponseTemplate::new(200).set_body_json(body)
    }
}

/// deSEC's zone-level rule that the retype case turns on: a CNAME may not coexist with any
/// other type at the same subname.
fn validate(zone: &BTreeMap<Key, Value>) -> Result<(), String> {
    for (subname, record_type) in zone.keys() {
        if record_type == "CNAME"
            && zone
                .keys()
                .any(|(other, other_type)| other == subname && other_type != "CNAME")
        {
            return Err(format!(
                "Record sets of type CNAME cannot coexist with other record sets at {subname:?}."
            ));
        }
    }
    Ok(())
}

fn not_found() -> ResponseTemplate {
    ResponseTemplate::new(404).set_body_json(serde_json::json!({"detail": "Not found."}))
}

fn rrset_json(
    zone: &str,
    subname: &str,
    record_type: &str,
    records: &[String],
    ttl: u32,
) -> serde_json::Value {
    let name = if subname.is_empty() {
        format!("{zone}.")
    } else {
        format!("{subname}.{zone}.")
    };
    serde_json::json!({
        "domain": zone,
        "subname": subname,
        "type": record_type,
        "name": name,
        "records": records,
        "ttl": ttl,
        "created": "2026-01-01T00:00:00Z",
        "touched": "2026-01-01T00:00:00Z",
    })
}

/// A webhook serving the real router on a real socket, backed by `mock`.
///
/// A real socket rather than `tower::ServiceExt::oneshot`, because the two things most worth
/// pinning — the exact `Content-Type` bytes and the absence of a duplicate header — are hyper
/// serialization concerns that `oneshot` bypasses entirely.
///
/// The refresh loop is *not* spawned. Tests drive [`Harness::reload`] instead, so nothing here
/// depends on wall-clock timing and a failure is never a flake.
pub struct Harness {
    pub base: String,
    pub mock: DesecMock,
    pub store: SnapshotStore,
    refresher: Refresher,
    _server: MockServer,
}

impl Harness {
    pub async fn start(zones: &[&str]) -> Self {
        let server = MockServer::start().await;
        let mock = DesecMock::new(zones);
        mock.mount(&server).await;

        let client = desec::Client::builder()
            .token(TOKEN)
            .base_url(format!("{}/api/v1", server.uri()))
            .max_retries(0)
            .max_rate_limit_wait(Duration::from_secs(2))
            .timeout(Duration::from_secs(4))
            .build()
            .unwrap();

        let store = SnapshotStore::new();
        let metrics = Arc::new(Metrics::new(false, "integration"));
        let owned: Vec<String> = zones.iter().map(|z| (*z).to_owned()).collect();

        let refresher = Refresher::new(
            client.clone(),
            store.clone(),
            Arc::clone(&metrics),
            owned.clone(),
            Vec::new(),
            Duration::from_secs(180),
            Duration::from_secs(21_600),
        );

        let app = router::router(router::AppState {
            store: store.clone(),
            applier: Arc::new(Applier::new(client, store.clone(), false)),
            metrics,
            filter: DomainFilter::include(owned),
            allow_empty_zone_set: false,
            max_body_bytes: 32 * 1024 * 1024,
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let harness = Self {
            base,
            mock,
            store,
            refresher,
            _server: server,
        };
        harness.reload().await;
        harness
    }

    /// One refresh pass, as the background loop would eventually do.
    pub async fn reload(&self) {
        let update = self.refresher.tick().await;
        self.store.publish(update).await;
    }

    pub fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap()
    }

    pub fn accept() -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static(MEDIA_TYPE),
        );
        headers
    }
}
