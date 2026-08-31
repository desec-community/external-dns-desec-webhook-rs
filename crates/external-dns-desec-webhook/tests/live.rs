//! Tests against the real deSEC API.
//!
//! `#[ignore]`d, so `cargo test` skips them. Run them deliberately:
//!
//! ```text
//! DESEC_TOKEN=… just live-test
//! ```
//!
//! The scaffolding below is a deliberate fork of `desec-rs`'s, at
//! `crates/desec/tests/live.rs` in that repository. It is duplicated rather than exported
//! because most of it is policy the two suites have to disagree about: the scratch prefix,
//! the parent zone, and how patient the client is. Fixes travel by hand; there are two
//! copies, not a library.
//!
//! The one thing that must **not** be shared is [`SCRATCH_PREFIX`]. Both suites sweep
//! leftovers by recognising their own names, so overlapping prefixes would have each deleting
//! the other's zones mid-run. `edns-webhook-test` and `desec-rs-test` are disjoint in both
//! directions.
//!
//! # What this layer is for
//!
//! Exactly one thing: deSEC rewrites record values on storage, and no offline test can see
//! it. `adjusting_storing_and_reading_back_is_a_fixpoint` in `adjust` round-trips through our
//! own `records_for`, so it agrees with itself by construction. Here the server is in the
//! loop.
//!
//! Everything else is already covered better elsewhere. `end_to_end` owns the wire protocol
//! against a stateful mock, so nothing here goes through a socket of ours or asserts anything
//! about framing, `Content-Type` or status codes.

#![allow(clippy::expect_used)]

mod probes;

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use desec::api::domains::{Domain, NewDomain};
use external_dns_desec_webhook::apply::Applier;
use external_dns_desec_webhook::convert::{endpoint_from_parts, is_provider_managed};
use external_dns_desec_webhook::metrics::Metrics;
use external_dns_desec_webhook::model::RrKey;
use external_dns_desec_webhook::refresh::Refresher;
use external_dns_desec_webhook::store::SnapshotStore;
use external_dns_desec_webhook::wire::{Changes, Endpoint, RecordTypeName};
use external_dns_desec_webhook::{adjust, client};
use tokio::runtime::Runtime;
use tokio::sync::{Mutex, OnceCell};

use probes::{Outcome, WEBHOOK_PROBES, looping};

/// Prefix every scratch domain shares. Disjoint from `desec-rs`'s; see the module docs.
const SCRATCH_PREFIX: &str = "edns-webhook-test";

/// How old a scratch domain must be before the sweep will delete it, so that a run happening
/// elsewhere keeps its zones.
const SWEEP_GRACE: Duration = Duration::from_secs(3600);

/// One runtime for the whole binary, entered by every test through [`live`].
///
/// `#[tokio::test]` builds a runtime per test and drops it at the end of that test, which
/// tears the shared client's pooled connection out from under anything still running. A
/// runtime that outlives every test avoids it.
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().expect("a tokio runtime can be built"))
}

/// Runs a test body on the shared runtime.
fn live<F: Future<Output = ()>>(body: F) {
    runtime().block_on(body);
}

/// Reads an environment variable, treating an empty value as absent, because an unset GitHub
/// Actions variable expands to the empty string rather than vanishing.
fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn token() -> String {
    env("DESEC_TOKEN").unwrap_or_else(|| {
        panic!(
            "DESEC_TOKEN is not set.\n\
             These tests talk to the real API, so they need a token from a test account with \
             perm_create_domain and perm_delete_domain.\n\
             Run them with: DESEC_TOKEN=… just live-test"
        )
    })
}

/// Parent zone for scratch domains, overridable with `DESEC_TEST_PARENT`.
///
/// Deliberately not `dedyn.io`: creating or deleting a child of a public suffix deSEC
/// registers locally also rewrites that suffix's delegation, and two of those colliding is
/// what strands a domain permanently.
fn parent_zone() -> String {
    env("DESEC_TEST_PARENT").unwrap_or_else(|| "desec-rs-test.shine.town".to_owned())
}

/// Serializes domain creation and deletion. deSEC's change tracker is not safe against two
/// domain writes overlapping; one can lose its zone while its database row is rolled back,
/// leaving a domain that answers `500` forever and holds a slot against `limit_domains`.
fn domain_write_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// The client used for scratch-zone setup and teardown, which is **not** the code under test.
///
/// Patient on purpose: it may wait out a per-minute bucket rather than failing the run, which
/// is the opposite of what the webhook's own client wants.
async fn admin_client() -> &'static desec::Client {
    static CLIENT: OnceCell<desec::Client> = OnceCell::const_new();
    CLIENT
        .get_or_init(|| async {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .with_test_writer()
                .try_init();
            desec::Client::builder()
                .token(token())
                .max_rate_limit_wait(Duration::from_secs(180))
                .timeout(Duration::from_secs(30))
                .build()
                .expect("admin client configuration is valid")
        })
        .await
}

/// The client the code under test uses, built the way the binary builds it.
///
/// Through `client::build` and never by hand: that function exists so the tuning cannot drift
/// between the binary and the tests, and a live suite that reached for
/// `desec::Client::builder` would be measuring a client nothing ships.
fn probe_client() -> desec::Client {
    client::build(
        token(),
        desec::DEFAULT_BASE_URL,
        desec::RateLimits::desec_defaults(),
    )
    .expect("client configuration is valid")
}

async fn create_domain(new: &NewDomain) -> desec::Result<Domain> {
    let _guard = domain_write_lock().lock().await;
    admin_client().await.domains().create(new).await
}

async fn delete_domain(name: &str) -> desec::Result<()> {
    let _guard = domain_write_lock().lock().await;
    admin_client().await.domains().delete(name).await
}

/// A throwaway zone, deleted by [`Scratch::destroy`].
struct Scratch {
    name: String,
    minimum_ttl: u32,
}

/// A scratch name, unique per test and per run without an RNG: the label separates concurrent
/// tests, the timestamp separates successive runs.
fn scratch_name(label: &str, parent: &str) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_nanos();
    format!("{SCRATCH_PREFIX}-{label}-{stamp:x}.{parent}")
}

/// How long ago [`scratch_name`] minted this name, or `None` if it did not mint it.
///
/// Stricter than a prefix test on purpose. A bare prefix would match the parent zone if it
/// ever shared the prefix, and could not tell a leftover from a zone another run is using
/// right now — which is what the age is for.
fn scratch_age(name: &str, now: Duration) -> Option<Duration> {
    let (first, _parent) = name.split_once('.')?;
    let (_label, stamp) = first
        .strip_prefix(SCRATCH_PREFIX)?
        .strip_prefix('-')?
        .rsplit_once('-')?;
    let minted = Duration::from_nanos(u64::try_from(u128::from_str_radix(stamp, 16).ok()?).ok()?);
    Some(now.saturating_sub(minted))
}

impl Scratch {
    async fn create(label: &str) -> Self {
        sweep_leftovers().await;

        let name = scratch_name(label, &parent_zone());
        let domain = create_domain(&NewDomain::new(&name))
            .await
            .unwrap_or_else(|err| panic!("could not create scratch domain {name}: {err}"));

        assert_eq!(domain.name, name);
        Self {
            name,
            minimum_ttl: domain.minimum_ttl,
        }
    }

    async fn destroy(self) {
        delete_domain(&self.name)
            .await
            .unwrap_or_else(|err| panic!("could not delete scratch domain {}: {err}", self.name));
    }
}

/// Deletes scratch domains left behind by an interrupted run. Once per process.
async fn sweep_leftovers() {
    static SWEPT: OnceCell<()> = OnceCell::const_new();
    SWEPT
        .get_or_init(|| async {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock is after the epoch");
            let stale: Vec<_> = admin_client()
                .await
                .domains()
                .list()
                .all()
                .await
                .expect("could not list domains")
                .into_iter()
                .filter(|domain| {
                    scratch_age(&domain.name, now).is_some_and(|age| age > SWEEP_GRACE)
                })
                .map(|domain| domain.name)
                .collect();

            for name in stale {
                eprintln!("sweeping leftover scratch domain {name}");
                if let Err(err) = delete_domain(&name).await {
                    eprintln!("  could not delete {name}: {err}");
                }
            }
        })
        .await;
}

/// Not `#[ignore]`d: the sweep decides what to delete, so its rule is worth checking without
/// a network and without an account.
#[test]
fn the_sweep_recognises_only_its_own_leftovers() {
    let now = Duration::from_secs(10_000);
    let age = |name: &str| scratch_age(name, now);

    let minted = scratch_name("probes", "example.test");
    assert!(age(&minted).is_some(), "{minted}");

    // Neither suite's prefix may match the other's names, or the two sweeps fight.
    assert_eq!(age("desec-rs-test-probes-1.example.com"), None);
    // Nor a parent zone that happens to start with the prefix.
    assert_eq!(age("edns-webhook-test.example.com"), None);
    assert_eq!(age("example.com"), None);
    // Minted shape, unparseable stamp.
    assert_eq!(age("edns-webhook-test-probes-zz.example.com"), None);

    assert_eq!(
        age("edns-webhook-test-probes-1.example.com"),
        Some(now - Duration::from_nanos(1))
    );
}

/// One RRset that did not survive the round trip through deSEC.
struct Divergence {
    id: &'static str,
    asked_for: Vec<String>,
    reported: Vec<String>,
}

/// The property the whole design rests on, measured against the real API.
///
/// A settled cluster must cost no writes. Three passes over one scratch zone:
///
/// 1. the first apply writes every probe in one atomic request;
/// 2. the second compares against the snapshot as the write's own response left it;
/// 3. the third compares against the snapshot as a fresh `GET` rebuilt it.
///
/// Passes 2 and 3 are not redundant. Pass 2 asks whether deSEC's echo of the `PATCH` agrees
/// with what we asked for; pass 3 asks whether what it serves back later agrees too, which is
/// the only place an asynchronous rewrite would show.
///
/// Four probes are expected to write again on every pass. That is not a flaw in the test:
/// `LOC`, `SVCB` and `HTTPS` with parameters are rewritten by deSEC in ways nothing absorbs,
/// and pinning the set is how a fix to any of them gets noticed. See `probes::Outcome`.
#[test]
#[ignore = "talks to the real API; run with `just live-test`"]
fn a_reconcile_settles_except_for_the_known_write_loops() {
    live(async {
        let scratch = Scratch::create("probes").await;
        let zone_name = scratch.name.clone();

        let client = probe_client();
        let store = SnapshotStore::new();
        let metrics = Arc::new(Metrics::new(false, "live"));
        let refresher = Refresher::new(
            client.clone(),
            store.clone(),
            Arc::clone(&metrics),
            vec![zone_name.clone()],
            Vec::new(),
            Duration::from_secs(180),
            Duration::from_secs(21_600),
        );
        // No cooldown: this measures what the three applies below write, and a zone left
        // alone because deSEC refused it earlier would read as a fixpoint that was reached.
        let applier = Applier::new(client, store.clone(), false, Duration::ZERO);

        // Everything is collected before the zone is destroyed, so a newly failing assertion
        // does not also leak a domain.
        let outcome = async {
            store.publish(refresher.tick().await).await;
            let snapshot = store.load();
            assert!(snapshot.is_populated(), "the first refresh found nothing");
            assert_eq!(
                snapshot
                    .zones
                    .get(&zone_name)
                    .expect("the scratch zone was listed")
                    .minimum_ttl,
                scratch.minimum_ttl,
                "the zone's own TTL floor has to come from the API"
            );

            // No TTL, as a Kubernetes source emits, so adjustment clamps against the real
            // minimum rather than an assumed 3600.
            let sources: Vec<Endpoint> = WEBHOOK_PROBES
                .iter()
                .map(|probe| Endpoint {
                    dns_name: format!("{}.{}", probe.subname, zone_name),
                    targets: vec![probe.target.to_owned()],
                    record_type: RecordTypeName::new(probe.record_type),
                    ..Endpoint::default()
                })
                .collect();

            let (adjusted, tally) = adjust::adjust(sources, &snapshot.zones);
            assert_eq!(tally.dropped(), 0, "adjustment dropped a probe: {tally:?}");
            assert_eq!(adjusted.len(), WEBHOOK_PROBES.len());

            let changes = Changes {
                create: adjusted.clone(),
                ..Changes::default()
            };

            let first = applier.apply(&changes).await;
            let second = applier.apply(&changes).await;
            store.publish(refresher.tick().await).await;
            let third = applier.apply(&changes).await;

            (adjusted, first, second, third, store.load())
        }
        .await;

        scratch.destroy().await;

        let (adjusted, first, second, third, snapshot) = outcome;
        let total = WEBHOOK_PROBES.len();
        let loops = looping().len();

        // Pass 1: one request carrying every probe. Exactly one is the atomicity guarantee,
        // and nothing should be suppressed on a zone we have just seen empty.
        assert!(first.error.is_none(), "{:?}", first.error);
        assert_eq!(first.report.written, vec![(zone_name.clone(), total)]);
        assert_eq!(first.report.zones_failed, 0);
        assert!(!first.report.timed_out);
        assert_eq!(
            first.report.suppressed,
            external_dns_desec_webhook::plan::Tally::default(),
            "nothing should have been suppressed on the first write"
        );

        // What deSEC rewrote on the way in, as the production signal sees it.
        let rewritten: BTreeSet<&str> = first
            .report
            .normalized
            .iter()
            .filter_map(|normalized| id_of(&normalized.key))
            .collect();
        let expected_rewritten: BTreeSet<&str> = WEBHOOK_PROBES
            .iter()
            .filter(|probe| probe.outcome.is_rewritten())
            .map(|probe| probe.id)
            .collect();
        assert_eq!(
            rewritten, expected_rewritten,
            "the set of values deSEC rewrote is not the set probes::Outcome records"
        );

        // Passes 2 and 3: identical for everything but the known loops.
        for (label, pass) in [("second", &second), ("third", &third)] {
            assert!(pass.error.is_none(), "{label}: {:?}", pass.error);
            assert!(!pass.report.timed_out, "{label} pass hit its deadline");
            assert_eq!(
                pass.report.suppressed.identical,
                (total - loops) as u64,
                "{label} pass: wrong number of changes recognised as no-ops"
            );
            // Each asserted on its own: the right total with the wrong distribution is the
            // failure that looks like success.
            assert_eq!(pass.report.suppressed.delete_absent, 0, "{label}");
            assert_eq!(pass.report.suppressed.no_managed_zone, 0, "{label}");
            assert_eq!(pass.report.suppressed.unusable, 0, "{label}");

            let written: Vec<(String, usize)> = pass.report.written.clone();
            assert_eq!(
                written,
                vec![(zone_name.clone(), loops)],
                "{label} pass should rewrite exactly the known loops"
            );
            let looped: BTreeSet<&str> = pass
                .report
                .normalized
                .iter()
                .filter_map(|normalized| id_of(&normalized.key))
                .collect();
            assert_eq!(
                looped,
                looping().iter().map(|probe| probe.id).collect(),
                "{label} pass rewrote a different set than probes::Outcome records"
            );
        }

        // The relist landed, and the write is reflected in it.
        let zone = snapshot.zones.get(&zone_name).expect("still served");
        assert!(zone.touched.is_some(), "the forced relist did not happen");

        // Set equality rather than lookups: a fresh deSEC zone also holds apex SOA, NS,
        // DNSKEY, CDS and CDNSKEY, all of which `is_provider_managed` hides, so this is exact.
        let served: BTreeSet<&str> = zone
            .rrsets
            .keys()
            .filter(|key| !is_provider_managed(&key.subname, &key.record_type))
            .filter_map(id_of)
            .collect();
        let expected: BTreeSet<&str> = WEBHOOK_PROBES.iter().map(|probe| probe.id).collect();
        assert_eq!(
            served, expected,
            "the zone holds a different set than we wrote"
        );

        // The fixpoint itself: what we report back has to be what external-dns asked for,
        // except where `Outcome` says otherwise and names what covers the difference.
        let mut unexpected: Vec<Divergence> = Vec::new();
        let mut settled: Vec<&str> = Vec::new();
        for probe in WEBHOOK_PROBES {
            let asked_for = adjusted
                .iter()
                .find(|endpoint| {
                    endpoint.dns_name == format!("{}.{}", probe.subname, zone_name)
                        && endpoint.record_type.is(probe.record_type)
                })
                .expect("every probe was adjusted");
            let key = zone
                .rrsets
                .keys()
                .find(|key| id_of(key) == Some(probe.id))
                .expect("checked by the set equality above");
            let value = &zone.rrsets[key];
            let reported = endpoint_from_parts(
                &zone_name,
                &key.subname,
                &key.record_type,
                value.records(),
                value.ttl,
            );

            match (probe.outcome, reported.targets == asked_for.targets) {
                // Reported as asked for, which is what Fixpoint and Rejoined promise.
                (Outcome::Fixpoint | Outcome::Rejoined(_), true) => settled.push(probe.id),
                // Documented to differ, and it does. Absorbed says who covers it; Loops says
                // nobody does.
                (Outcome::Absorbed(_) | Outcome::Loops(_), false) => {}
                // Either a promise broke or a documented difference quietly went away. Both
                // mean the classification no longer describes the API.
                _ => unexpected.push(Divergence {
                    id: probe.id,
                    asked_for: asked_for.targets.clone(),
                    reported: reported.targets.clone(),
                }),
            }
        }

        println!(
            "\n{} of {total} probes round-trip unchanged; {loops} are known write loops.",
            settled.len()
        );

        assert!(
            unexpected.is_empty(),
            "probes::Outcome no longer describes what deSEC does:\n\n{}\n",
            unexpected
                .iter()
                .map(|divergence| format!(
                    "  {}\n    external-dns asked for : {:?}\n    we report              : {:?}",
                    divergence.id, divergence.asked_for, divergence.reported
                ))
                .collect::<Vec<_>>()
                .join("\n\n")
        );
    });
}

/// The probe a stored RRset belongs to, matched on the pair that identifies it to deSEC.
fn id_of(key: &RrKey) -> Option<&'static str> {
    WEBHOOK_PROBES
        .iter()
        .find(|probe| {
            probe.subname == key.subname.as_payload()
                && key.record_type.as_str() == probe.record_type
        })
        .map(|probe| probe.id)
}
