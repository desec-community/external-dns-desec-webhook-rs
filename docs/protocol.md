# The external-dns webhook protocol, as it actually behaves

Every fact here was established by reading `kubernetes-sigs/external-dns` at **v0.21.0**, and
each is annotated with the file it came from so the next maintainer can re-verify rather than
re-derive. That matters more than usual, because the project's own published specification is
wrong in one load-bearing place.

Facts that constrain code are also doctests on `src/wire.rs`. This document is the provenance;
the doctests are the enforcement.

## The endpoints

| Method | Path | Expects | Source |
| --- | --- | --- | --- |
| GET | `/` | 200, a serialized `endpoint.DomainFilter` | `provider/webhook/webhook.go:newProvider` |
| GET | `/records` | 200, a JSON array of `Endpoint` | `webhook.go:Records` |
| POST | `/records` | exactly **204** | `webhook.go:ApplyChanges` |
| POST | `/adjustendpoints` | 200, a JSON array of `Endpoint` | `webhook.go:AdjustEndpoints` |

## The published spec is wrong about the negotiate body

`api/webhook.yaml` documents:

```yaml
filters:
  - example.com
```

There is no such key. The wire type is `endpoint.DomainFilter`, whose `MarshalJSON`
(`endpoint/domain_filter.go:196`) emits `domainFilterSerde`:

```go
type domainFilterSerde struct {
    Include      []string `json:"include,omitempty"`
    Exclude      []string `json:"exclude,omitempty"`
    RegexInclude string   `json:"regexInclude,omitempty"`
    RegexExclude string   `json:"regexExclude,omitempty"`
}
```

A webhook emitting `filters` therefore negotiates an **empty** filter, and an empty
`DomainFilter` matches every domain (`domain_filter.go:matchFilter`, where an empty filter list
returns the `emptyval` of `true`). The failure is silent and the consequence is that external-dns
believes it manages everything.

## Status codes: only `500..=510` is retried

`webhook.go:isRetryableError`:

```go
func isRetryableError(statusCode int) bool {
    return statusCode >= http.StatusInternalServerError && statusCode <= http.StatusNotExtended
}
```

A retryable status becomes `provider.NewSoftError`, which external-dns logs and retries on the
next reconcile. **Everything else is permanent**, including:

- `429 Too Many Requests` — the status a throttled provider most wants to send, and the one that
  makes external-dns abandon the sync instead of waiting
- `408 Request Timeout` — which `tower_http`'s timeout layer emits by default
- `413 Payload Too Large` — which axum's `DefaultBodyLimit` emits
- `415 Unsupported Media Type` — which `axum::Json` **as an extractor** emits, because
  external-dns sends the webhook media type rather than `application/json` on ApplyChanges

All four are avoided in `src/router.rs`, and `src/error.rs` has a test over every error variant
asserting the status is `204 || 500..=510`.

## The media type is compared as a string

`provider/webhook/api/httpapi.go:34`:

```go
MediaTypeFormatAndVersion = "application/external.dns.webhook+json;version=1"
```

and `webhook.go:newProvider`:

```go
if ct := resp.Header.Get(webhookapi.ContentTypeHeader); ct != webhookapi.MediaTypeFormatAndVersion {
    return nil, fmt.Errorf("wrong content type returned from server: %s", ct)
}
```

Go `!=` on the raw header. Note the absence of a space after the semicolon. Any writer that
round-trips the value through a media-type parser — Rust's `mime`, and therefore `axum::Json` and
`axum_extra::TypedHeader(ContentType(..))` — normalizes the separator to `"; "` and fails the
handshake. The Magicloud crate needed a custom actix responder for exactly this reason.

Checked **only** on the negotiate response, and the negotiate call is the one that happens once
at external-dns startup and is fatal when it fails.

## Timeouts, and the absence of retries

`webhook.go:newProvider`:

```go
client := extdnshttp.NewInstrumentedClient(&http.Client{Timeout: readTimeout + writeTimeout})
```

Defaults from `pkg/apis/externaldns/types.go`: `webhook-provider-read-timeout` 5s and
`webhook-provider-write-timeout` 10s, so **15 seconds for the whole round trip**.

`requestWithRetry` (5 attempts, backoff) wraps **only** the negotiate call. `Records`,
`ApplyChanges` and `AdjustEndpoints` each get exactly one attempt per reconcile.

## `AdjustEndpoints` never sees the registry's records

`controller/controller.go`:

```go
regRecords, _ := c.Registry.Records(ctx)           // GET /records
endpoints, _ := c.Registry.AdjustEndpoints(source) // POST /adjustendpoints
plan := ...; plan = plan.Calculate()
err = c.Registry.ApplyChanges(ctx, plan.Changes)   // POST /records
```

and `registry/txt/registry.go:418`:

```go
func (im *TXTRegistry) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
    return im.provider.AdjustEndpoints(endpoints)
}
```

A pure passthrough. The ownership TXT records are synthesized in `TXTRegistry.ApplyChanges`,
*after* the plan, and appended to the changes. Three consequences:

1. They arrive with **`TTL 0`**, because `generateTXTRecordWithFilter` builds them with
   `endpoint.NewEndpoint`, which is `NewEndpointWithTTL(..., TTL(0), ...)`. So TTL clamping has to
   exist on the write path, not only in adjustment.
1. The apex artefact (below) reaches us only at `POST /records`, so the out-of-zone check has to
   be there too.
1. Nothing normalized in `/adjustendpoints` applies to them.

## `providerSpecific` is an array

`endpoint/endpoint.go:276`:

```go
ProviderSpecific ProviderSpecific `json:"providerSpecific,omitempty"`
```

where `ProviderSpecific` is `[]ProviderSpecificProperty`, each `{name, value}`. Modelling it as a
map drops duplicate names and changes the JSON the TXT registry compares against. The
`externaldns-webhook` crate on crates.io has it as a map.

## Every field may be absent or `null`

Every field of `Endpoint` and of `plan.Changes` is `omitempty`, and Go marshals a nil slice or map
as `null`. In serde, `#[serde(default)]` covers *absent* only — `"targets": null` still fails with
"invalid type: null" — so each collection field also needs a `null_as_default` deserializer.

`recordTTL` needs an explicit rename: `rename_all = "camelCase"` on `record_ttl` gives
`recordTtl`, which matches nothing and silently deserializes as absent forever. The
`externaldns-webhook` crate has the same shape of bug with `updateOld`/`updateNew` renamed to
PascalCase, so every update it receives is empty.

## The `--txt-prefix` apex artefact

With the default prefix, the ownership record for an endpoint at a zone apex is named *outside*
the zone. Managing `example.com` yields a TXT at `externaldns-a-example.com`, a sibling of
`example.com` under `.com`. deSEC scopes every API call to a zone the account owns, so it cannot
be created, and the sync never converges.

This is an external-dns naming bug ([#5010]), not a deSEC one. The documented fix is
`--txt-prefix=externaldns-%{record_type}.`, which places the record inside the zone.

We report it rather than translating it away. A provider-side synthetic rename would hide a name
external-dns still believes it owns, and the ownership record is the one thing that must mean the
same to both sides. What we do instead is skip the unplaceable change, log the fix by name, and
let the no-op suppression stop the resulting `txt/force-update` from costing a write.

## Other requirements from the docs

From `docs/tutorials/webhook-provider.md`:

- Always send a complete response body, even on errors — this is what lets the client pool the
  TCP connection.
- Keep error bodies well under 1 MiB. A deSEC bulk rejection carries one entry per RRset, so ours
  are truncated.
- Tolerate client cancellation without assuming rollback is needed.

## Crates evaluated and rejected

Recorded so the decision is not silently revisited.

- **`external-dns-sdk` 0.7.1** (kubi-zone, MIT). Last commit 2024-07-05: axum 0.7, thiserror 1.0,
  and a dependency on `kubizone-common`.
- **`externaldns-webhook` 2026.2.23** (Magicloud, Apache-2.0). Actively maintained, but:
  `providerSpecific` typed as a map; `updateOld`/`updateNew` serde-renamed to PascalCase, so
  updates deserialize as empty; a closed `RecordType` enum with no CAA, DS, TLSA or HTTPS, which
  makes an unknown mnemonic a deserialization failure and therefore a permanent 4xx; and
  `eyre::Result` in the public trait signature.

The protocol is about 250 lines. Implementing it in-tree costs less than working around either.

[#5010]: https://github.com/kubernetes-sigs/external-dns/issues/5010
