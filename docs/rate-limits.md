# The request budget

deSEC's [documented throttles](https://desec.readthedocs.io/en/latest/rate-limits.html), for the
scopes this provider touches:

| Scope | Rate | What it covers |
| --- | --- | --- |
| `dns_api_cheap` | 10/s, 50/min | reads: the zone list, and listing a zone's records |
| `dns_api_per_domain_expensive` | 2/s, 15/min, 100/h, **300/day** | RRset writes, **per zone** |
| `user` | **2000/day** | any authenticated request at all |

A `429` carries `Retry-After` in seconds. The `desec` crate models every scope as a sliding
window, keys the per-domain one by zone name, and paces requests rather than collecting `429`s —
but that state lives only in memory, so a restart forgets it while the server does not.

## Reads

One `GET /domains/` per refresh tick, whatever the zone count, and then one
`GET /domains/{zone}/rrsets/` for each zone whose `touched` moved since the last tick.

At the 180s default, on a settled account:

```
  86400 / 180                        = 480  zone lists per day
  zones × (86400 / 21600)            =   4  forced re-reads per zone per day
```

So twenty zones is about 560 requests a day, or 28% of the account budget.

**Why not 60s.** The zone-list poll alone would be 1440 a day — 72% of the account budget spent
on discovering that nothing has changed, before a single record is read or written. The webhook
warns at startup when the configuration it was given exceeds 1000.

`--refresh-interval` is unrelated to external-dns's `--interval`. external-dns can reconcile
every minute; `/records` is served from cache, so those reconciles cost nothing.

## Writes

At most one atomic bulk `PATCH` per zone per `ApplyChanges`, and none at all when nothing would
change. On a settled cluster the steady state is **zero writes**, however often external-dns
reconciles.

The 300/day per-zone cap is therefore only reachable by genuinely changing 300 things in a zone
in a day. If you are approaching it, `webhook_zone_writes_total` with
`--metrics-zone-labels` shows which zone:

```promql
increase(webhook_zone_writes_total{result="ok"}[24h]) > 250
```

## Reading the metrics

The two that matter:

**`webhook_changes_suppressed_total{reason="identical"}`** climbing while
`webhook_zone_writes_total` stays flat is the design working. external-dns is asking for writes
and we are declining to make them. If `zone_writes_total` climbs on an idle cluster instead, the
write loop is back — check `webhook_adjust_mutations_total{kind="ttl_clamped"}` next, since a TTL
disagreement is the likeliest cause.

**`webhook_desec_requests_total{outcome="would_block"}` versus `outcome="throttled"`.** The first
is our own limiter pacing us, which is intended. The second means deSEC pushed back, which has
only two causes worth considering:

- something else shares the account — cert-manager's deSEC solver, `dnscontrol`, the web UI. The
  documented rates are the *account's* budget, not ours. Give the webhook a share with
  `--rate-limit dns_api_per_domain_expensive=1/s,7/min`.
- the process restarted and lost its in-memory windows. This is also why `/healthz` ignores deSEC
  entirely: restarting a throttled webhook makes the throttling worse, not better.
