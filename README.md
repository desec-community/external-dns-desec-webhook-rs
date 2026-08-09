# external-dns-desec-webhook

An [external-dns] webhook provider for [deSEC], built to stay inside deSEC's rate
limits and inside external-dns's request budget.

```yaml
# external-dns Helm values.yaml
provider:
  name: webhook
  webhook:
    image:
      repository: ghcr.io/desec-community/external-dns-desec-webhook-rs
      tag: "<version goes here>"
    env:
      - name: DESEC_TOKEN_FILE
        value: /etc/desec/token
      - name: DESEC_DOMAIN_FILTER
        value: example.com
extraArgs:
  - --txt-prefix=externaldns-%{record_type}.
```

## deSEC rate limits, external-dns request budget

deSEC caps RRset writes at 300 per day per domain and any authenticated request at 2000
per day for the whole account. external-dns reconciles every minute by default, which is
1440 cycles a day. With this default, a provider that writes once per cycle exhausts the
write budget in 5 hours. A provider that blocks while throttled runs past external-dns's
15-second client timeout and takes external-dns down with it.

This webhook makes some choices to avoid getting rate-limited:

- **The webhook's `/records` and `/adjustendpoints` endpoints never call deSEC.** They are
  served from a snapshot that a background task refreshes on its own schedule, so they
  answer in microseconds whatever the API is doing.
- **An external-dns cycle with no real change makes no request.** TTLs are normalized
  against the zone's own `minimum_ttl` before external-dns compares them, and any write
  that would not change stored state is dropped.
- If the deSEC API throttles a request, the webhook leaves the API alone until the
  `Retry-After` has elapsed, rather than poll the API on every external-dns cycle.

For those reasons, **you can leave external-dns's `--interval` to whatever you like.** The
webhook ensures that a low `--interval` does not exhaust the request budget. Instead, you
can set the webhook property `--refresh-interval` (`WEBHOOK_REFRESH_INTERVAL`); the webhook
reports what this will cost at startup.

## Configuration

Every setting is a flag and an environment variable; `--help` is authoritative.

| Variable | Flag | Default | |
| --- | --- | --- | --- |
| `DESEC_TOKEN` | `--api-token` | | token, or use the file form |
| `DESEC_TOKEN_FILE` | `--api-token-file` | | preferred in Kubernetes |
| `DESEC_DOMAIN_FILTER` | `--domain-filter` | | **required**, comma-separated |
| `DESEC_EXCLUDE_DOMAIN` | `--exclude-domain` | | comma-separated |
| `DESEC_API_URL` | `--api-url` | `https://desec.io/api/v1` | |
| `WEBHOOK_LISTEN` | `--listen` | `127.0.0.1:8888` | provider endpoints |
| `WEBHOOK_ADMIN_LISTEN` | `--admin-listen` | `0.0.0.0:8080` | health and metrics |
| `WEBHOOK_REFRESH_INTERVAL` | `--refresh-interval` | `180s` | independent of `--interval` |
| `WEBHOOK_MAX_ZONE_AGE` | `--max-zone-age` | `6h` | forced re-list backstop |
| `WEBHOOK_MAX_THROTTLE_COOLDOWN` | `--max-throttle-cooldown` | `1h` | `0` disables |
| `WEBHOOK_DRY_RUN` | `--dry-run` | `false` | |
| `WEBHOOK_ALLOW_EMPTY_ZONE_SET` | `--allow-empty-zone-set` | `false` | see below |
| `WEBHOOK_METRICS_ZONE_LABELS` | `--metrics-zone-labels` | `false` | |
| `WEBHOOK_MAX_BODY_BYTES` | `--max-body-bytes` | `33554432` | |
| `WEBHOOK_RATE_LIMIT` | `--rate-limit` | | `scope=rate[,rate]`, for shared accounts |
| | `--check-config` | | validate and exit |

Log level comes from `RUST_LOG`, e.g. `RUST_LOG=external_dns_desec_webhook=debug`.

## Things that will bite you

**Set `--txt-prefix=externaldns-%{record_type}.` on external-dns.** With the default
prefix, the ownership TXT record for a *zone-apex* endpoint is named outside the zone:
managing `example.com` yields a TXT at `externaldns-a-example.com`, which is a sibling
of `example.com` under `.com`, not a child of it. deSEC scopes every API call to a
zone you own, so the record cannot be created and the sync never converges. This is an
external-dns naming bug ([external-dns#5010]); we report it rather than papering over
it, because a provider-side translation would hide a name external-dns still believes
it owns.

**Run it as a sidecar, on loopback.** The provider endpoints have no authentication.
Binding them to `0.0.0.0` grants DNS write access to every pod that can reach the
port; the webhook warns at startup if you do.

**A domain filter is mandatory.** With `--registry=txt` external-dns filters deletions by
owner ID, so a zone it has never written to is safe — but `--registry=noop` reports an
empty owner ID and that filter is skipped entirely, at which point every record in a zone
we report that the source does not produce becomes a deletion. There is deliberately no
"manage the whole account" mode.

**`--webhook-provider-read-timeout=30s` should no longer be needed.** It was a
workaround for the previous provider blocking while throttled. Handlers here finish
well inside the default 5s+10s budget, and answer `503` rather than hanging when
deSEC is unavailable. The one case that may still want a longer timeout is a first
refresh over a very large number of zones; `--refresh-interval` and `/readyz` are the
knobs to watch.

**Unknown record types pass through.** CAA, DS, TLSA, HTTPS and SVCB all work, and a
mnemonic this build has never heard of is forwarded rather than rejected.

## Debugging without a cluster

```console
$ cargo install external-dns-desec-webhook
$ DESEC_TOKEN=… DESEC_DOMAIN_FILTER=example.com external-dns-desec-webhook &
$ curl -H 'Accept: application/external.dns.webhook+json;version=1' \
    http://127.0.0.1:8888/records | jq
```

`/metrics` on port 8080 is where the interesting answers are: a rising
`changes_suppressed_total{reason="identical"}` on an idle cluster means external-dns
is still planning writes that we are declining to make, and
`desec_requests_total{status="429"}` means something else is sharing the account.

## Further reading

`docs/protocol.md` records the webhook wire format and where in external-dns each
detail was verified, `docs/rate-limits.md` works through the request budget, and
`docs/deployment.md` has the full manifests.

## License

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

[desec]: https://desec.io
[external-dns]: https://github.com/kubernetes-sigs/external-dns
[external-dns#5010]: https://github.com/kubernetes-sigs/external-dns/issues/5010
