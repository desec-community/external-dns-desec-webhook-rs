# Testing

This webhook has four layers of tests, one needing network access to a real deSEC account.

## 1. Unit and property tests

`cargo test`. The four modules where every historical bug lived (`wire`, `convert`, `model`,
`adjust`) have no internal dependencies, no async, and no mocking, so they are tested directly.

## 2. Integration tests against a stateful deSEC mock

`cargo test --test end_to_end`. The real router on a real socket, against an in-memory deSEC in
`tests/common/mod.rs`.

The stateful mock is ported from the Go provider's `desecMock`.

It enforces two rules that are about zone state rather than about individual requests:

- `POST /rrsets/` is create-only
- a CNAME may not coexist with another type at the same subname

The mock uses a real socket rather than a `tower::ServiceExt::oneshot`, because the `Content-Type`
bytes and absence of a duplicate header are `hyper` serialization concerns that `oneshot` bypasses.

Mock tests are deterministic and don't depend on wall-clock timing.

## 3. The offline lab: real external-dns, no cluster, no Docker

<!-- TODO: Since the offline lab wasn't made yet, this needs to be revisited. -->

**external-dns runs without Kubernetes.** `source/fake.go` says so in its own doc comment:
it "provides dummy endpoints for testing/dry-running of dns providers without needing an
attached Kubernetes cluster". `SingletonClientGenerator::KubeClient` is lazy (`kubeOnce.Do`),
so no API client is ever constructed when the only source is `fake`.

So the whole production shape can run as three local processes:

```
  external-dns  ──HTTP──▶  this webhook  ──HTTP──▶  a fake deSEC
  (real Go binary)         (127.0.0.1:8888)         (in-memory)
```

Every part of the contract that unit tests cannot reach is exercised: the real Go client's
handshake, its exact `Accept` and `Content-Type` headers, its 15-second budget, its
`500..=510`-only retry classification, the TXT registry's ownership records with their `TTL 0`,
and the plan calculator's own idea of what counts as a change.

### Running it

```console
$ external-dns \
    --provider=webhook \
    --webhook-provider-url=http://127.0.0.1:8888 \
    --source=fake \
    --registry=txt --txt-owner-id=lab \
    --txt-prefix='externaldns-%{record_type}.' \
    --domain-filter=example.com \
    --policy=sync \
    --once --log-level=debug
```

`--once` runs a single reconcile and exits.

### The assertion that matters

`NewFakeSource` seeds its generator with a **fixed** value (`rand.NewSource(9673)`) but advances
it on each `Endpoints()` call. Two consequences, and the second is the useful one:

- Within one long-running process, each cycle generates *different* random targets, so
  `--interval=5s` would produce a genuine change every cycle. Not useful.
- Across separate `--once` processes the seed resets, so **every run desires exactly the same
  state**.

Which gives the regression test for the bug this project exists to fix:

1. Run `--once`. The webhook writes the records. Note `webhook_zone_writes_total`.
1. Run `--once` again, unchanged.
1. **`webhook_zone_writes_total` must not have moved**, and
   `webhook_changes_suppressed_total{reason="identical"}` must have.

That is the exact scenario in which the Go provider issued one write per zone per cycle, and it
is checkable in about twenty seconds on a laptop.

`--source=fake` also emits an endpoint for the zone apex (`example.com` with no subdomain), so
the run additionally exercises the `--txt-prefix` footgun. With the default prefix you should
see the webhook log `no managed deSEC zone contains this name` and name the fix; with
`externaldns-%{record_type}.` set as above, you should not.

### What still needs building

- **A standalone fake deSEC.** The one in `tests/common/mod.rs` is a `wiremock::Respond`, usable
  only from a Rust test. The lab needs it as its own process — an `examples/fake_desec.rs`
  serving the same zone rules over axum, plus a `/__state` endpoint to assert against and a
  mutation counter to read. Perhaps 150 lines, and it reuses the validation logic.
- **A driver script.** `scripts/lab.sh`: start the fake deSEC, start the webhook, run
  external-dns twice, diff the counters, tear down.
- **A pinned external-dns.** There are no release binaries — external-dns ships only as
  container images — so this means either `buildGoModule` in `nix/external-dns.nix` (needs a
  `vendorHash`, which is one build to obtain) or an `EXTERNAL_DNS_BIN` escape hatch for a
  binary you already have.

Ordered that way because each step is useful on its own: the fake deSEC alone lets you drive the
webhook by hand with `curl`.

### Where a real cluster is still needed

Only for what the fake source cannot represent:

- **Source behaviour**: Ingress, Service and Gateway annotations, `external-dns.alpha.kubernetes.io/ttl`,
  and the CRD source. These change what arrives at `/adjustendpoints`, and a fake source does
  not exercise any of them.
- **The real registry lifecycle over time**: ownership migration, `--txt-owner-id` changes, and
  what happens when two external-dns instances share a zone.
- **Anything about the deSEC API itself**: whether long TXT records split where we assume, and
  what the real rate limiter does under load. That is the `just live-test` layer, not the lab.

## 4. Live tests

`just live-test`, `#[ignore]`d so `just test` and CI skip them. Needs `DESEC_TOKEN` from a test
account with `perm_create_domain` and `perm_delete_domain`; `DESEC_TEST_PARENT` overrides the
parent zone for scratch domains.

Thread-capped at 2, lower than `desec-rs`'s 4: a full four-endpoint reconcile cycle spends more
of the 300-writes-a-day per-domain budget than a library test does.

The one question only this layer can answer is the open one in the design: **where deSEC splits
a TXT record over 255 bytes.** We emit a single chunk and store whatever the server returns, so
the split should never matter — but that is an argument, not evidence, and a long `DKIM` record
on a real zone is how to get the evidence.
