# Findings

Nine things that changed the implementation, found by reading source rather than documentation.
Each section says what the mechanism is, what would have gone wrong, and what the code does about
it.

Two of these corrected claims I had already written into comments. Those corrections are marked,
because a wrong reason in a comment is worse than no reason at all.

______________________________________________________________________

## 1. `max_retries(0)` on the deSEC client is load-bearing, not cautious

### The mechanism

`desec-rs` retries a failed request only when replaying it is safe:

```rust
fn is_replayable(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS)
}
```

`PATCH` is absent, which is correct — the deSEC API lets `PATCH` create RRsets, so it is not
idempotent in general. Our writes are all bulk `PATCH`, so a 5xx or a dropped connection is *not*
retried. Good.

But look at where the 429 branch sits in `client.rs`:

```rust
if res.status == StatusCode::TOO_MANY_REQUESTS {
    let retry_after = res.retry_after();
    self.inner.limiter.record_throttled(&scopes, retry_after);

    let delay = retry_after.unwrap_or_else(|| self.backoff(attempt));
    if attempt > self.inner.retry.max_retries || delay > self.inner.retry.max_delay {
        return Err(Error::RateLimited { .. });
    }
    tokio::time::sleep(delay).await;
    continue;
}

// 5xx is worth a retry, but only where replaying is safe: ...
```

The 429 handling comes **before** the `is_replayable` gate, and `continue`s regardless of method.
That is a deliberate and defensible choice by the library: a throttled request was rejected
*before* the server processed it, so replaying it cannot duplicate an effect. From the API's point
of view, retrying a throttled `PATCH` is perfectly safe.

It is not safe from *our* point of view, because we are on a clock.

### The arithmetic

Defaults are `max_retries: 3` and `max_delay: 60s`. So the behaviour depends on what deSEC's
`Retry-After` says:

| `Retry-After` | What happens with defaults |
| --- | --- |
| 120s | `delay (120) > max_delay (60)` → returns immediately. Fine. |
| 30s | sleeps 30s, three times, then returns. **~90 seconds.** |
| 60s | sleeps 60s, three times. **~180 seconds.** |

external-dns allows **15 seconds** for the whole round trip
(`--webhook-provider-read-timeout` 5s + `--webhook-provider-write-timeout` 10s) and does **not**
retry within a cycle. So any `Retry-After` in the 1–60s band produces a handler that overruns the
client budget by an order of magnitude — and the 1–60s band is exactly what deSEC's per-minute
bucket (`dns_api_per_domain_expensive`, 15/min) yields.

That is the Go provider's failure mode, reproduced exactly, from a default.

### What we do

```rust
.max_retries(0)          // the critical line
.max_rate_limit_wait(Duration::from_secs(2))
.max_retry_delay(Duration::from_secs(1))
.timeout(Duration::from_secs(4))
```

With `max_retries(0)`, `attempt (1) > max_retries (0)` is true on the first 429, so
`Error::RateLimited` comes back immediately with the server's `Retry-After` intact. We turn that
into a `503` plus a `Retry-After` header, and external-dns retries on its own schedule instead of
inside our handler.

Nothing is lost by not retrying, because `record_throttled` has *already* run by that point — the
shared limiter has learned the penalty, so every other task backs off without having to earn its
own 429.

`max_rate_limit_wait(2s)` matters for a second, subtler reason: `record_throttled` caps the stored
penalty at `max_wait`. `Scope::User` is in every request's scope set, so a `Retry-After: 3600`
recorded uncapped would idle the entire client for an hour on the strength of one response.

### Correction to an earlier claim

A comment in `apply.rs` originally justified this with "three retries honouring a
`Retry-After: 120` sleeps about six minutes". That is wrong: 120 exceeds the 60s
`max_retry_delay`, so the library gives up at once. The test now uses `Retry-After: 30`, which is
genuinely inside the dangerous window, and the comment says so.

### Pinned by

`apply::tests::a_throttled_write_answers_503_far_inside_the_client_budget` — asserts a `503`, the
`Retry-After` passed through, and a wall-clock elapsed under two seconds.

______________________________________________________________________

## 2. Ownership TXT records never reach `/adjustendpoints`

### The mechanism

external-dns's reconcile loop, from `controller/controller.go`:

```go
regRecords, err := c.Registry.Records(ctx)            // our GET  /records
endpoints, err := c.Registry.AdjustEndpoints(source)  // our POST /adjustendpoints
plan := &plan.Plan{Current: regRecords, Desired: endpoints, ...}
plan = plan.Calculate()
err = c.Registry.ApplyChanges(ctx, plan.Changes)      // our POST /records
```

and the TXT registry's own implementation, `registry/txt/registry.go`:

```go
func (im *TXTRegistry) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
    return im.provider.AdjustEndpoints(endpoints)
}
```

A pure passthrough. So `/adjustendpoints` sees exactly the endpoints your sources produced — an
Ingress host, a Service, a `DNSEndpoint` CRD — and nothing else.

The `externaldns-a.www TXT "heritage=external-dns,..."` companion records are not source
endpoints. They are **synthesized** inside `TXTRegistry.ApplyChanges`, *after* `plan.Calculate()`,
and appended to the change set that then goes to `POST /records`. They exist for the first time at
the moment they are written.

### Why it matters

Three consequences, and the first is the one that would have quietly reintroduced the original bug.

**They arrive with `TTL 0`.** `generateTXTRecordWithFilter` builds them with
`endpoint.NewEndpoint(...)`, and `NewEndpoint` is:

```go
func NewEndpoint(dnsName, recordType string, targets ...string) *Endpoint {
    return NewEndpointWithTTL(dnsName, recordType, TTL(0), targets...)
}
```

deSEC rejects `ttl: 0`. So if TTL clamping lived only in `/adjustendpoints` — which is the natural
place for it, and where it fixes the *source* TTL problem — every ownership record would fail to
write. Clamping has to exist on the write path too, against the zone's own `minimum_ttl`.

**The apex artefact arrives only here.** With the default `--txt-prefix`, the companion record for
an endpoint at a zone apex is named *outside* the zone (see §7 of `docs/protocol.md`). The check
that skips unplaceable names therefore has to be in `plan.rs`, not just in `adjust.rs`.

**Nothing normalized in adjustment applies to them.** Any canonicalization we do to source
endpoints — dots, case, TXT quoting — has to be applied independently on the write path, because
these records bypass it entirely.

### What we do

`plan::resolve` clamps TTL and resolves the zone for *every* endpoint in the change set,
independently of `adjust`. It looks like duplicated logic. It is not: the two run on disjoint
inputs.

### Pinned by

`plan::tests::a_change_arriving_without_a_ttl_is_clamped_here_too` and
`end_to_end::an_ownership_record_arriving_without_a_ttl_is_stored_with_the_zone_minimum`.

______________________________________________________________________

## 3. `#[tokio::test(start_paused = true)]` cannot be used with a real socket

### The mechanism

Paused time is how you write instant, deterministic tests of timeouts and intervals: timers fire
when you advance the clock rather than when wall-clock time passes. Tokio also **auto-advances**
paused time — when the runtime has no work left to do, it jumps the clock forward to the next
timer deadline rather than idling.

"No work left to do" is judged from the runtime's perspective. A task blocked on a real TCP socket
is parked in the reactor, waiting on `epoll`; from the scheduler's point of view there is nothing
runnable. So the runtime concludes it is idle and advances the clock — straight past the client's
own timeout.

### What that looked like

The first version of the throttle test used `start_paused = true` with a `wiremock` server. It
failed with a status of 500 instead of 503, and printing the error gave:

```
Internal("HTTP transport error")
```

Not a 429 at all. The 4-second `desec::Client` timeout had fired instantly, before the loopback
request could complete, so the code under test never saw the mocked 429 and reported a transport
failure instead. The test was measuring nothing, and would have "passed" for the wrong reason had
the assertion been looser.

### What we do

Any test that speaks to a socket — every `wiremock` test in this crate — uses real time. The
throttle test measures `std::time::Instant::elapsed()` and asserts it is under two seconds, which
is a generous bound for a loopback request and still two orders of magnitude below the 90 seconds
the library defaults would have produced.

Paused time remains the right tool for testing the refresh interval or a deadline in isolation,
against no I/O at all. It is simply incompatible with the integration layer.

______________________________________________________________________

## 4. `axum::Json` as an *extractor* would have failed every single write

### The mechanism

`axum::Json` used as a return type is fine. Used as an **extractor**, it first checks the request's
`Content-Type` and rejects with `415 Unsupported Media Type` if it is not `application/json` (or a
`+json` suffix it recognises).

external-dns sends this on `POST /records`:

```
Content-Type: application/external.dns.webhook+json;version=1
```

Whether axum's suffix matching accepts that exact string is beside the point, because of §5 below:
**415 is a 4xx, and external-dns treats every 4xx as permanent.** Not a slow retry — a permanent
abandonment of the sync.

So the natural, idiomatic Rust handler signature

```rust
async fn apply_changes(State(state): State<AppState>, Json(changes): Json<Changes>) -> ...
```

risks making *every* ApplyChanges a fatal error, with a failure mode that looks nothing like a
media-type problem from the external-dns side: you would see the sync stop, with a log line about
an unexpected status code.

### What we do

Read the body as bytes under an explicit cap and deserialize by hand:

```rust
let body = read_body(request, state.max_body_bytes).await?;
let changes: Changes = serde_json::from_slice(&body)
    .map_err(|e| WebhookError::internal(format!("could not decode changes: {e}")))?;
```

This also removes the media-type question entirely, gives us the debug body dump the Go provider
had to bolt on separately, and lets a malformed body be a `500` rather than a `400` (see §5).

### Pinned by

`end_to_end::apply_accepts_the_webhook_content_type_and_answers_exactly_204`.

______________________________________________________________________

## 5. Four HTTP statuses that look right are all permanent failures

### The mechanism

The entirety of external-dns's retry policy for a webhook provider, from
`provider/webhook/webhook.go`:

```go
func isRetryableError(statusCode int) bool {
    return statusCode >= http.StatusInternalServerError && statusCode <= http.StatusNotExtended
}
```

`500..=510`, and nothing else. A retryable status becomes `provider.NewSoftError`, which
external-dns logs and retries on the next reconcile. Everything else propagates as a hard error.

That makes four statuses actively dangerous, and each of them is what some default would emit:

| Status | Emitted by | Why it is the wrong answer |
| --- | --- | --- |
| **429** Too Many Requests | the obvious hand-written choice when throttled | The single most semantically apt status is permanent. Sending it abandons the sync over a condition that clears in a minute. |
| **408** Request Timeout | `tower_http::timeout::TimeoutLayer` by default | A timeout is meant to *encourage* a retry; this prevents one. |
| **413** Payload Too Large | axum's `DefaultBodyLimit` (2 MiB) | A large cluster's `/adjustendpoints` body runs to tens of MB, so the default limit alone would wedge it. |
| **415** Unsupported Media Type | `axum::Json` as an extractor | §4. |

### What we do

- **Throttled is `503`**, with the server's `Retry-After` passed through and clamped to
  `[1, 3600]`.
- The router's backstop timeout is configured to emit `408`, which a `map_response` layer then
  rewrites into a `503` *with a body*. The 408 never reaches the wire; the two-step exists only
  because the remap needs something to recognise.
- The body cap is hand-rolled via `axum::body::to_bytes(body, limit)`, so an oversized body is our
  `500` rather than the layer's `413`.
- Bodies are read as bytes, so there is no 415 path.
- **Even a malformed request body is `500`, not `400`.** This one is a judgement call: a body we
  cannot parse will probably not parse next time either, so the retry is wasted. But the cost of a
  wasted retry is one request a minute, and the cost of being wrong in the other direction is a
  permanently stopped sync. And the likeliest cause of an unparseable body is not a broken
  external-dns but a *newer* one, sending a field we do not model — in which case retrying while
  someone reads the logs is exactly right.

### Pinned by

`error::tests::every_variant_maps_to_a_status_external_dns_retries`, which enumerates every
`WebhookError` variant and asserts the status is in `500..=510`. It exists specifically to fail
when a future contributor reaches for the 429 that looks so obviously correct.

______________________________________________________________________

## 6. `DS` at a subname is yours; `DS` at the apex is deSEC's

### The mechanism

deSEC signs zones itself, so some record types are read-only. `desec-rs` exposes:

```rust
pub fn is_dnssec_managed(&self) -> bool {
    matches!(self, CDNSKEY | CDS | DNSKEY | DS | NSEC3PARAM | RRSIG | SOA)
}
```

with a doc comment that turns out to be the whole finding:

> `DS` is the reason this is qualified: at the apex it belongs to the parent zone and deSEC
> manages it, but at a subname it is an ordinary delegation record that callers write.

That is a real distinction, not pedantry. `DS` at the apex of `example.com` is published by
`.com`. `DS` at `sub.example.com` is how *you* delegate `sub` to someone else's nameservers, and
it is an ordinary record you may well want external-dns to manage from a CRD.

The naive reading — "filter out every type where `is_dnssec_managed()` is true" — would have made
subdomain delegation records invisible to external-dns: unreportable, and therefore
unmanageable.

### What we do

Scope the rule by position, not by type alone:

```rust
pub fn is_provider_managed(subname: &Subname, record_type: &RecordType) -> bool {
    if matches!(record_type, RecordType::RRSIG | RecordType::NSEC3PARAM) {
        return true;  // never user-managed, at any name
    }
    subname.is_apex() && (record_type.is_dnssec_managed() || *record_type == RecordType::NS)
}
```

Apex `NS` is in there for the same reason as `SOA`: it is deSEC's delegation set, not ours.

### Why hide them at all

They can never be written successfully — deSEC rejects the attempt — so any plan that touches one
produces a request that can only fail. Under `--registry=txt` a deletion would be filtered out by
owner ID and no harm done, but under `--registry=noop` that filter is skipped (§7) and an apex
`SOA` becomes a delete request every single cycle, forever.

They are also filtered at the **`/records` edge only**, and kept in the snapshot. That is
deliberate: the snapshot is a mirror of what deSEC holds, and if a create for one of these
arrived, comparing it against a snapshot that had dropped it would make it look *new* and cost a
rejected write. Kept, it compares as identical and costs nothing.

### Pinned by

`convert::tests::desec_managed_records_are_hidden_only_where_desec_owns_them` and
`end_to_end::records_desec_manages_itself_are_not_reported`.

______________________________________________________________________

## 7. An empty `/records` cannot cause deletion — but a missing filter can

**This section corrects a claim I had written into eight comments and three docs.** I had asserted
that an empty record set under `--policy=sync` means "delete everything you own". It does not, and
the real mechanism is more interesting.

### What I got wrong

`plan.calculateChanges` decides per DNS-name row:

```go
for key, row := range t.rows {
    switch {
    case len(row.current) == 0:        // nothing there now
        // ... append to changes.Create
    case len(row.candidates) == 0:     // nothing wanted, something there
        changes.Delete = append(changes.Delete, row.current...)
    case len(row.candidates) > 0:
        p.appendTakenDNSNameChanges(t, changes, key, row)
    }
}
```

`Current` is what *we* reported. An empty `/records` makes `len(row.current) == 0` for every row,
which takes the **Create** branch. Deletion requires the opposite: a record we reported as present
with nothing desired to match it. An empty answer therefore cannot delete anything.

### Why the 503 is still right

The honest reason is not deletion but **truthfulness**. `/records` is external-dns's only source
of ground truth for the current state of the zone. An empty array does not say "I do not know", it
says "I know, and there is nothing there" — and external-dns plans against that claim:

- Every endpoint becomes a Create, so a provider without no-op suppression issues a write storm
  against a 300-writes-a-day-per-zone budget. Ours suppresses them, but that is defence in depth,
  not a licence to lie.
- The TXT registry sees no ownership records and re-derives ownership for everything, which is
  wasted work at best and confusing in the logs at worst.

`503` is retried; a claim is believed. So: no snapshot yet → `503`; zero managed zones → `503`
behind an explicit `--allow-empty-zone-set`; a *stale* snapshot → `200` with stale data, because
old truth beats no truth. And a zone the account holds but we have never listed is left out of the
snapshot entirely rather than published empty.

### The real deletion hazard, and why the filter is mandatory

Look at the last line of `calculateChanges`:

```go
if p.OwnerID != "" {
    changes.Delete = endpoint.FilterEndpointsByOwnerID(p.OwnerID, changes.Delete)
}
```

`p.OwnerID` comes from `c.Registry.OwnerID()`. With the TXT registry that is your
`--txt-owner-id`, so deletions are filtered to records external-dns has actually claimed — a zone
it has never written to is safe even if we report it.

But `registry/noop/noop.go`:

```go
func (im *NoopRegistry) OwnerID() string {
    return ""
}
```

With `--registry=noop`, `OwnerID` is empty, the guard is false, and **the ownership filter is
skipped entirely**. Every record we report that the source does not produce becomes a Delete.

That is the argument for a mandatory `--domain-filter`, and it is a much sharper argument than the
one I originally wrote: an unfiltered webhook over a whole deSEC account is one `--registry=noop`
away from deleting DNS the cluster never knew about. The webhook refuses to start without a filter,
and enforces it twice — in the negotiate response *and* as zone admission in the refresher — rather
than trusting the peer to respect what it was told.

______________________________________________________________________

## 8. `prometheus-client`'s derive puts Rust variant names on the wire

### The mechanism

The obvious way to type a metric label is an enum:

```rust
#[derive(EncodeLabelValue)]
pub enum Outcome { Ok, Throttled, WouldBlock, Unauthorized, Error }
```

The derive encodes the variant's **Rust identifier**, verbatim. So a scrape produces:

```
webhook_desec_requests_total{op="Write",outcome="WouldBlock"} 1
```

Not `would_block`. Not `write`. This surfaced as a test failing on an assertion I was confident
about, which is the cheap way to find it; the expensive way is a dashboard query that silently
matches nothing.

### Why it matters more than it looks

Metric names and label values are an **interface**. Dashboards, alert rules and runbooks are
written against them by people who will never read this crate. Deriving them from Rust identifiers
means a routine refactor — renaming `WouldBlock` to `RateLimited`, say — silently breaks every
alert that referenced it, with no compile error anywhere.

### What we do

Plain `&'static str` label values behind named constants, so the wire strings are written down
once and visible:

```rust
pub mod outcome {
    pub const OK: &str = "ok";
    pub const THROTTLED: &str = "throttled";
    pub const WOULD_BLOCK: &str = "would_block";
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const ERROR: &str = "error";
}
```

The type safety lost is small — these are only ever passed to one function — and the guarantee
gained is that the wire format cannot change without editing the string.

### Why this particular split earns its keep

`outcome="would_block"` means our own limiter declined before making a request: pacing working as
designed. `outcome="throttled"` means deSEC pushed back, which has only two causes worth
considering — something else shares the account, or we restarted and lost the limiter's in-memory
sliding windows. An operator needs to tell those apart, so the label values need to be stable
enough to alert on.

### Pinned by

`metrics::tests::a_local_refusal_and_a_server_throttle_are_distinguishable`.

______________________________________________________________________

## 9. `desec::api::rrsets::Rrset` cannot be constructed

### The mechanism

`Rrset` is `#[non_exhaustive]` with public fields and `Serialize + Deserialize`, and no
constructor. That is a reasonable design for a response type: the API owns the shape, new fields
should not be breaking, and there is no sensible way for a caller to invent a `created` timestamp.

It also means it can only ever come *from* the API. A cache cannot hold one and hand it back.

I hit this by writing `Rrset::from_parts(...)` in the `/records` handler on the assumption such a
thing existed, because my converter took `&Rrset`.

### Why it is a design signal, not just an inconvenience

The snapshot deliberately does not store `Rrset`. It stores a key and a value:

```rust
struct RrKey   { subname: Subname, record_type: RecordType }
struct RrValue { records: Vec<String>, ttl: u32 }   // sole ctor sorts + dedups
```

split that way because the key is what identifies an RRset to deSEC and the value is what a write
would change — and because `RrValue`'s constructor sorting and deduplicating is what makes `==` a
valid "would this write change anything?" test. Neither side promises an order, so comparing
unsorted lists would report a change whenever the two happened to differ, which is a write.

So the conversion boundary belongs at the parts, not at the response type. The workaround was the
right shape all along:

```rust
pub fn endpoint_from_parts(
    zone: &str, subname: &Subname, record_type: &RecordType, records: &[String], ttl: u32,
) -> Endpoint
```

with `endpoint_from_rrset(zone, &Rrset)` kept as a thin wrapper for the refresh path, where the
value genuinely did come off the wire.

### Worth knowing upstream

If `desec-rs` ever grows a caching layer, it will hit exactly this. Either `Rrset` gains a
`from_parts` constructor, or the cache stores parts — and the parts turn out to be the better
representation anyway, because they are what the write API takes.
