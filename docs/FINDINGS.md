# Findings

Two batches, from two different kinds of work.

**§1–§9** changed the implementation, and were found by reading source rather than documentation.
Each says what the mechanism is, what would have gone wrong, and what the code does about it.

**§10–§19** were found by *running* the Go provider this replaces, and are correlated against
this codebase here rather than acted on. They come from [external-dns-desec-provider#26][pr26]
— a year of production fixes — from the review of it, and from
[sshine/external-dns-desec-provider#2][pr2], another operator's account of the same failure from
a four-cluster deployment. Some describe holes this design has that the Go provider does not.
Some describe problems this design retired outright, recorded so they are not re-litigated. One
is a correction to §4. **None of them is a decision**; several are almost certainly not worth
their complexity.

Corrections to claims I had already written into comments or docs are marked, because a wrong
reason in a comment is worse than no reason at all.

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

______________________________________________________________________

## 10. A `429` with no `Retry-After` teaches the limiter nothing

### The mechanism

`desec-rs`, `ratelimit.rs`:

```rust
pub(crate) fn record_throttled(&self, scopes: &ScopeSet, retry_after: Option<Duration>) {
    let Some(retry_after) = retry_after else {
        return;
    };
    ...
}
```

No header, no penalty. The sliding windows are untouched too, because they record *grants* and a
throttled request was never granted. So a millisecond after a bare 429, the limiter's model of the
account is exactly what it was a millisecond before: admissible.

Our `classify` covers for this on the wire, but only there:

```rust
desec::Error::RateLimited { retry_after, .. } => WebhookError::unavailable(
    "deSEC returned 429 Too Many Requests",
    retry_after.unwrap_or(Duration::from_secs(60)),
),
```

That fills in the `Retry-After` we send external-dns. It does not reach the limiter, and per §1
external-dns retries on its own `--interval` regardless of what that header says. So the next
reconcile's `POST /records` goes straight to the wire and earns another 429, and so does the one
after it.

CodeRabbit found this in the Go provider's transport and proposed recording a conservative default
in the missing-header branch. The same one-line shape applies here, except it belongs upstream in
`desec-rs`.

### How likely it is

Not very, and that is the interesting part. deSEC runs Django REST Framework throttles, which
always set `Retry-After` from `wait()`. The realistic sources of a bare 429 are all
*intermediaries*: a corporate proxy, a CDN in front of a self-hosted deSEC reached via
`--api-url`, a service-mesh limiter, or deSEC's own front end shedding load before the application
sees the request.

Which is to say: the case where the client most needs to back off unprompted is the one case where
it doesn't.

### Where we stand

Unhandled. The remedy is upstream and small, and the only argument against it is that a penalty
invented from nothing is a guess. `max_rate_limit_wait` already bounds how wrong that guess can be
(§11), which makes it a cheap one.

______________________________________________________________________

## 11. The limiter's memory of a throttle is two seconds long

**This qualifies a claim in §1.**

### The mechanism

`record_throttled` again, one line further down:

```rust
let Some(until) = Instant::now().checked_add(retry_after.min(self.max_wait)) else { return };
```

§1 reads `.min(self.max_wait)` as a safety valve, and it is one: `Scope::User` is in every
request's scope set, so an uncapped `Retry-After: 3600` would idle the entire client for an hour on
the strength of one response. But the cap does not merely *bound* the penalty. It **is** the
penalty. With `max_rate_limit_wait(2s)`, every throttle deSEC reports — thirty seconds, twelve
hours — becomes the same two-second local backoff.

So §1's closing sentence needs a clause:

> Nothing is lost by not retrying, because `record_throttled` has *already* run by that point — the
> shared limiter has learned the penalty, so every other task backs off without having to earn its
> own 429.

True for two seconds. After that, every task earns its own.

### Why it is nevertheless close to right

What paces this provider is not the penalty, it is the sliding windows — and those are accurate for
as long as we are the only client on the account. Around them:

- The refresher doubles its own backoff to 900s on a failed tick, so a throttled read path stops
  asking without needing the limiter's help.
- The write path has no backoff of its own, but a write is gated behind `Applier::gate`, capped at
  one bulk `PATCH` per zone per apply, and suppressed entirely when nothing would change. Its
  worst case is one request per zone per external-dns interval, which is not hammering.

The two-second penalty therefore only matters in one situation: when the windows are wrong because
**something else is spending the same budget**. Then the penalty is the only corrective signal
there is, and it lasts two seconds.

### The case the windows cannot model

That situation is not hypothetical. It is what [pr2] is about:

> This fixes a scenario where requests to the rrset endpoint kept piling up in a way that 4
> clusters exhausted the 50/min limit within seconds.

Four processes, one token. Each one paces itself correctly against limits that describe the
*account*, each believes it may spend `50/min` of `dns_api_cheap`, and between them they may spend
50\. Every participant is well-behaved and the account is throttled anyway. See §18.

### Where we stand

Raising `max_rate_limit_wait` would lengthen the memory and lengthen the worst-case in-handler
wait by the same amount (§15) — the two are the same number, which is the awkward part. Decoupling
them upstream (a penalty ceiling separate from the wait ceiling) is the clean fix and is a
`desec-rs` change, not one here.

______________________________________________________________________

## 12. The write path emits no deSEC request metrics at all

### The mechanism

`op::WRITE` is defined in `metrics.rs` and used nowhere but `metrics.rs`'s own test. Following the
call sites:

- `record_desec_error` and `record_desec_ok` are called only from `refresh.rs`.
- `record_write` is called only from `router.rs`, and only ever with `"ok"`.
- `ApplyReport::zones_failed` is set by `apply` and read by nothing.

So `webhook_desec_requests_total` only ever carries `op="list_zones"` and `op="list_rrsets"`. The
headline diagnostic in `docs/rate-limits.md` —

> **`webhook_desec_requests_total{outcome="would_block"}` versus `outcome="throttled"`**

— describes only the read path. On the write path, which is the one with the 300-per-zone-per-day
budget, a throttle and a rejection are indistinguishable: both are one increment of
`soft_errors{endpoint="apply"}` and one `apply_duration_seconds{reason="error"}` sample. (A
deadline is distinguishable, via `reason="timeout"`.)

### Why the plumbing is missing

Not an oversight so much as a consequence of where the abstraction was drawn. `write_zone` calls
`classify(&error)` and returns a `WebhookError`, so by the time the router sees an outcome the
`desec::Error` is gone — and `WebhookError::Unavailable` covers throttled, would-block,
unauthorized *and* our own deadline as one variant. `Applier` deliberately holds no `Arc<Metrics>`,
which is what keeps `apply.rs` testable without one, and `ApplyOutcome` was meant to carry
everything the router needs. It carries everything the router needs to *answer*, and nothing it
needs to *count*.

### A second-order consequence

`docs/rate-limits.md` budgets against successes:

```promql
increase(webhook_zone_writes_total{result="ok"}[24h]) > 250
```

deSEC's throttle counts *requests* — DRF records the hit before the view runs — so a rejected write
spends a slot in `dns_api_per_domain_expensive` just as a successful one does. A zone burning its
300 a day on writes deSEC keeps rejecting reads as `0` on that query, right up to the point where
it starts getting 429s instead.

### Where we stand

Mechanically small: give `Applier` the metrics handle, call `record_desec_error(op::WRITE, &error)`
in `write_zone` before `classify` flattens it, and let `record_write` see failures so
`result="throttled"` and `result="error"` stop being labels that only tests produce. The cost is
one dependency edge into `apply.rs`. The alternative — widening `ApplyOutcome` to carry the
`desec::Error` — keeps the edge out but leaks the client's error type through the module boundary
the `WebhookError` conversion exists to close.

______________________________________________________________________

## 13. A throttle never says how long, anywhere an operator will look

### The mechanism

`desec::Error::RateLimited`:

```rust
#[error("still rate limited after {attempts} attempts")]
RateLimited {
    attempts: u32,
    retry_after: Option<Duration>,
    #[source] body: ApiError,
},
```

`retry_after` appears in no format string, and `body` is a `#[source]`, so it is not in `Display`
either. `apply.rs` logs `error = %error`, which therefore renders as *"still rate limited after 1
attempts"* and nothing else. The read path is quieter still:

```rust
if error.is_rate_limited() {
    tracing::warn!(zone = %name, "throttled while re-reading zones; publishing what was read");
    break;
}
```

— no error, no duration. Meanwhile deSEC's own body, sitting unread in `RateLimited::body`, says
`{"detail": "Request was throttled. Expected available in 45000 seconds."}`.

### Why it matters

This is the Go finding in a different mechanism. There:

> Without a logger `retryablehttp` swallows the 429 and its retry wait, which is how the ~12.5h
> sleep was invisible in the logs.

Nothing hangs here — that is what §1 is for — so the consequence is smaller. But the number that
tells an operator whether they are thirty seconds or twelve hours from working is equally absent,
and it is the first thing anyone will want. The `Retry-After` does reach external-dns as a response
header, where nobody reads it, and reaches `/metrics` as nothing at all.

### Where we stand

Two `tracing` fields in this crate, and arguably one line upstream to put `retry_after` into
`RateLimited`'s `Display` — which would fix it for every consumer of the crate rather than this
one.

______________________________________________________________________

## 14. The documented way to turn on debug logging turns off the interesting logs

### The mechanism

`docs/deployment.md`'s migration table and the README both give:

| Old | New | Note |
| --- | --- | --- |
| `WEBHOOK_LOGLEVEL` | `RUST_LOG` | e.g. `external_dns_desec_webhook=debug` |

One directive, with a target. The default it replaces has two:

```rust
EnvFilter::new("external_dns_desec_webhook=info,warn")
```

— this crate at info, **and a bare `warn` covering everything else**. Setting the documented value
drops that second directive, so nothing from any other target is admitted below `ERROR` — which is
every diagnostic the other crates emit. Turning on debug logging therefore silences:

| Event | Target | Level |
| --- | --- | --- |
| `"giving up on a throttled request"` | `desec::client` | `WARN` |
| `"local rate limit reached, waiting"` | `desec::ratelimit` | `DEBUG` |
| the per-request span and `"response"` | `desec::client` | `DEBUG` |

The first is the only line that says a 429 ended a request. The second is the only evidence the
limiter is pacing us at all. None of the three is under `external_dns_desec_webhook`, and all three
are what you reached for debug logging to see.

### The request log that is not there either

`TraceLayer::new_for_http()` puts its span, its on-request event and its on-response event at
`DEBUG` under `tower_http::trace`, which the bare `warn` never admits. The only thing the layer
contributes at the default level is `DefaultOnFailure`'s `ERROR` line on a 5xx — emitted inside a
span that is itself disabled, so it names neither the path nor the duration.

That means there is no *"started"* / *"completed"* pair. The Go provider had exactly this hole and
closed it, in `internal/server/log.go`:

> A private `logrus.New()` here silently discards the start/completion lines (they were logged
> below the default level and to a separate sink), which hid that a `/records` handler had started
> but never completed during the deSEC throttle hang.

The consequence differs: there the missing line hid a hang, and here the handlers are bounded, so
it hides only latency. But the apply histogram loses its worst samples too (§15), so latency is not
recoverable from metrics either.

### What actually works

```
RUST_LOG=external_dns_desec_webhook=debug,desec=debug,tower_http=debug,warn
```

which nobody is going to guess, and which the docs do not say.

### Where we stand

Either document the long form, or add a `--log-level` that composes the filter and leaves
`RUST_LOG` as the escape hatch for people who want the firehose. The second is what
`WEBHOOK_LOGLEVEL` was, and what the migration table implicitly promises an equivalent of.

______________________________________________________________________

## 15. The nine-second budget does not start when the request does

**This corrects the diagram at the top of `apply.rs`.**

### The mechanism

That diagram says 15s client, 12s router layer, 9s handler deadline, 4s per attempt. Two waits sit
outside it.

**The gate.**

```rust
pub async fn apply(&self, changes: &Changes) -> ApplyOutcome {
    let _gate = self.gate.lock().await;                    // unbounded
    ...
    let timed_out = tokio::time::timeout(DEADLINE, self.write_all(...)).await.is_err();
```

The clock starts *after* the mutex is acquired. If external-dns overlaps two reconciles — which is
the only reason the gate exists — the second request waits an unmetered amount of time and then
grants itself a fresh nine seconds. Only the router's 12s layer bounds the total, and when that
fires the client gets the generic remapped 503 rather than the composed one with a real
`Retry-After`.

**The pacing wait.** `desec::Client`'s `timeout(4s)` is set on the `reqwest` client, so it covers
`send()` and the body read. `Limiter::acquire` runs before that, inside the same `execute` call,
and may sleep up to `max_rate_limit_wait`. The innermost bound is 2 + 4 = **6 seconds**, not 4.

In practice the 2s is only ever spent after a throttle: one bulk `PATCH` per zone per gated apply
never fills a `2/s` per-domain window, and eight concurrent zones do not trouble `user`'s
`2000/day`. So the pacing wait is reachable exactly when a penalty is live, which is exactly when
the handler is already slow. CodeRabbit raised the same arithmetic against the Go transport, where
it was worse — there the sleep was *inside* `http.Client.Timeout` and ate the budget rather than
extending it.

### The part that costs something

When the 12s layer fires, or external-dns hangs up, or the pod drains, the whole `apply` future is
dropped. `write_all`'s `JoinSet` goes with it, aborting the in-flight `PATCH`es, and:

- the `Arc<Mutex<Vec<_>>>` of per-zone outcomes is dropped, so which zones succeeded is unknown;
- `store.invalidate` is never called for the zones that were attempted;
- nothing is recorded — including `apply_duration_seconds`, whose stated purpose is that "a
  near-miss on the 15s client timeout is visible before it becomes an outage". The samples it
  loses are precisely the near-misses.

The snapshot damage is self-healing, which is worth stating because it bounds how much this
matters: a `PATCH` that landed moves the zone's `touched`, and `needs_relist` compares
server-supplied values, so the next tick re-reads the zone whether or not we invalidated it. What
does not heal is the metric. What is merely wasteful is a duplicate write, if external-dns replans
before the next tick.

### Where we stand

Fixing the gate ordering is two lines — start the clock at handler entry, or wrap the acquire in
the deadline — and it makes the diagram true rather than aspirational. Whether the dropped-future
case deserves defending is a genuine question: a `Drop` guard or a detached recorder is more
machinery than a self-healing failure justifies, and the honest answer may be to amend the comment
instead.

______________________________________________________________________

## 16. `snapshot_age_seconds` measures the zone list, not the records

### The mechanism

`store::publish`:

```rust
last_full_ok: if update.zone_list_ok { Some(Instant::now()) } else { current.last_full_ok },
```

and `zone_list_ok` is true whenever `GET /domains/` succeeded. `refresh.rs` sets it before reading
a single RRset, and its own test pins that it survives a mid-tick throttle:

```rust
// The zone list itself succeeded, so nothing is removed.
assert!(update.zone_list_ok);
assert!(update.error.is_some());
```

That is right for what the flag is *for*: a failed list is not evidence a zone has gone away (§7).
The problem is that `last_full_ok` is then reused as the snapshot's **age**, and age is what
`/readyz`, `webhook_snapshot_age_seconds` and the `age_s` field on the `/records` log line all
report.

So a webhook that lists zones happily every 180 seconds and has been throttled out of every RRset
read for six hours reports an age of a couple of minutes and answers `/readyz: ready`. The records
it is serving are six hours old. Per-zone truth exists — `Zone::listed_at`, which
`Zone::is_stale` already uses to schedule forced re-reads — and nothing surfaces it.

### The staleness question underneath

The Go provider capped staleness at 24 hours:

```go
// maxCacheStaleness caps how old a last-known-good record set may be before it is no longer
// served during a throttle window. Past it we prefer a 500 (retried next interval) over
// feeding external-dns a stale zone under --policy=sync, which could delete records that in
// fact still exist.
```

Here there is no cap at all. §7 states the position — "a *stale* snapshot → `200` with stale data,
because old truth beats no truth" — and it is stronger than the Go comment's fear, because §7 also
establishes that reported-but-absent records cannot cause a deletion the owner filter would not
already stop, and because `plan::build` suppresses deletes for RRsets the snapshot does not hold.

What a stale snapshot *can* do is the opposite of deletion. A record created out of band while we
were blind — cert-manager's ACME TXT, a hand-edited MX — is missing from what we report, so
external-dns takes the `len(row.current) == 0` branch, plans a Create, and we write over it. That
is a real overwrite rather than a phantom one, and its likelihood grows with age.

The author of the Go patch had arrived at the same doubt from the other direction, in [pr2]:

> I'm wondering if the 24h maxCacheStaleness should be configurable and default closer to the
> throttle window.

### Where we stand

Two separable things, and only the first is clearly worth doing.

1. **Report the right age.** `max(zone.listed_at.elapsed())` across the snapshot, exposed
   *alongside* the zone-list age rather than instead of it — the two mean different things and
   both are diagnostic. This costs nothing and makes the existing readiness bound honest, which is
   a precondition for arguing about the second point at all.
1. **Cap the age.** Refusing to serve past a bound trades a known-wrong answer for a `503`, and
   §7's argument is that the known-wrong answer is usually the better one. If it is ever added it
   should be a flag defaulting to *off* rather than a constant, and it should be per-zone rather
   than all-or-nothing — the Go version's all-or-nothing rule exists because it had no zone-level
   model, and this one does.

______________________________________________________________________

## 17. §4 claims a debug body dump that does not exist

**This corrects §4.**

Among the benefits §4 lists for reading the request body as bytes:

> gives us the debug body dump the Go provider had to bolt on separately

It does not. `router::apply_changes` reads the bytes, deserializes them, and drops them:

```rust
let body = read_body(request, state.max_body_bytes).await?;
let changes: Changes = serde_json::from_slice(&body)...
```

Nothing logs `body`. Reading as bytes *makes a dump possible* — the Go provider had to buffer and
rewind `r.Body` to get one — but the two lines were never written.

What the Go version dumped is worth keeping in mind, because the gap it filled is still open here.
Its commit exists to explain a live cluster logging `0 creates, 10 updates, 0 deletes` every
minute, and the fields that explained it — `UpdateOld`, `labels`, `providerSpecific` — are exactly
the ones no summary line shows. This provider's `changes_suppressed_total{reason="identical"}`
answers *how many* of those updates were spurious without answering *why*, so the diagnostic
question is the same one.

CodeRabbit's note on that commit applies to any version of it: bound what gets logged. A large
cluster's change set runs to megabytes, and one log line that size is its own incident.

______________________________________________________________________

## 18. Per-domain in-flight dedup solves a problem this design does not have

[pr2] adds a `fetchTracker`: a per-domain set of in-flight fetches, where a second concurrent fetch
for the same domain short-circuits to `FetchInProgressError` rather than going on the wire.

### Why the mechanism is moot here

There is only ever one fetcher. `GET /records` is served from the snapshot and touches no socket.
The only code that lists RRsets is `Refresher::tick`, which is one task, iterates zones
**sequentially** with a comment saying why, and caps itself at `MAX_RELISTS_PER_TICK`. Two fetches
of the same zone cannot overlap because no two fetches can overlap. On the write side
`Applier::gate` serializes applies outright.

A dedup map here would guard against a concurrency the architecture forbids, and would then be the
only thing stopping a future contributor from noticing they had introduced one.

### The part that is not moot

Note the "4 clusters" in the PR's own description. In-process dedup does not touch that, and its
author says so:

> limited per process, does not transcend clusters, although I would probably not share a DNS zone
> between clusters

Four processes sharing a token is §11's case: each paces itself against limits that describe the
account, each believes it may spend the whole allowance, and the account is throttled while every
participant is individually well-behaved. This provider's answer is manual partitioning —
`--rate-limit dns_api_cheap=12/s,12/min` — which `docs/rate-limits.md` documents for the
cert-manager case but not for the multi-cluster one, even though the arithmetic is the same and the
multi-cluster reader is the one who has to do it in their head.

### Where we stand

The dedup feature: no, and the reason recorded here so it does not get re-proposed. The
account-sharing problem: unsolved, and probably correctly unsolved — a shared limiter behind a
lease, or a leader among replicas, is a distributed-systems dependency for a webhook that
otherwise has none. What it does deserve is a paragraph in `rate-limits.md` addressed to the reader
running more than one cluster off one token.

______________________________________________________________________

## 19. The rest of the correlation

Everything else from [pr26] and its review, checked against this codebase and closed. Recorded
because "we looked and it was already handled" is only useful if it is written down.

| From the Go fork | Status here |
| --- | --- |
| One atomic bulk write per domain, so a retype is not two rejected requests | `plan::build` emits one `ZonePlan` per zone; `a_record_type_change_becomes_one_atomic_request` |
| Strip the trailing dot from the reported `dnsName` | `convert::canonical_name`; `reported_dns_names_never_carry_a_trailing_dot` |
| Bump `nrdcg/desec` for the apex `subname,omitempty` bug | pinned against `desec-rs` by `a_change_to_the_apex_addresses_the_empty_subname` |
| A throttle must become a soft error, never a 429 | §5; `every_variant_maps_to_a_status_external_dns_retries` |
| Serve cached records during a throttle window | the premise rather than a fallback — reads never call the API |
| Thread the request context so a hung call can be cancelled | no call to hang: §1 removes the retry sleep, and `apply` bounds itself |
| **Review:** invalidate the cache after a successful write | `store::apply_confirmed` folds in the *response* and sets `touched: None`, which is more than the review asked for |
| **Review:** probe and commit are not serialized, so two callers can both pass a full window | does not reproduce — `Limiter::acquire` probes and claims under one lock hold, and `a_refused_acquire_claims_nothing` pins that a blocked request claims nothing |
| **Review:** the proactive sleep is inside the HTTP client's timeout | does not reproduce — `reqwest`'s `timeout` covers only `send()`, so the limiter wait is additive; that is its own arithmetic, in §15 |
| **Review:** `Retry-After` truncates to `0` for a sub-second window | `RETRY_AFTER_BOUNDS = (1, 3600)`; `retry_after_is_clamped_into_range` |
| **Review:** `Retry-After` may be an HTTP-date | `Res::retry_after` parses both forms and clamps to `MAX_RETRY_AFTER` |
| **Review:** pin GitHub Actions to full-length SHAs | done throughout `.github/`, with version and date comments |
| Log the throttle's `Retry-After` and deSEC's detail body | **open** — §13 |

[pr2]: https://github.com/sshine/external-dns-desec-provider/pull/2
[pr26]: https://github.com/michelangelomo/external-dns-desec-provider/pull/26
