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

### When a write is refused

deSEC counts a request before it runs the view, so a rejected write spends a slot just as a
successful one does. That matters because external-dns reads only the status code of our answer:
it comes back every `--interval` whatever `Retry-After` we sent, and a zone that earned a 429
would earn another one every cycle — sixty an hour against a budget of three hundred a day, each
one deepening the hole.

So a zone deSEC refuses is left alone until the wait it named elapses, up to
`--max-throttle-cooldown` (1h). external-dns sees the same `503` it would have seen anyway; the
worst case at deSEC drops from one request per zone per `--interval` to one per zone per hour.

The cap is really a probe interval. deSEC can name a wait of twelve hours, and honouring that
literally would leave a zone unwritable for a working day on the strength of one response; at an
hour we spend one request an hour finding out whether it still means it. Setting it to `0` turns
the cooldown off, which restores sending writes deSEC has already said it will refuse.

Like the limiter's sliding windows, this lives only in memory. A restart now discards two kinds
of throttle memory rather than one.

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
  `--rate-limit dns_api_per_domain_expensive=1/s,7/min`. The same arithmetic applies to more than
  one cluster on one token, which is the case people hit without expecting to: each process paces
  itself correctly against limits that describe the account, and between them they overspend it.
- the process restarted and lost its in-memory windows. This is also why `/healthz` ignores deSEC
  entirely: restarting a throttled webhook makes the throttling worse, not better.

**`webhook_zone_writes_total{result="cooling_down"}`** is a write we declined to make, and it is
the one outcome here with no other trace: no request, so nothing reaches
`webhook_desec_requests_total`, and a `503` indistinguishable from any other in
`webhook_soft_errors_total`. If DNS is not updating and nothing appears to be failing, this is
where to look.

```promql
rate(webhook_zone_writes_total{result="cooling_down"}[5m]) > 0
```

A related tell: `webhook_apply_duration_seconds{reason="error"}` that is *fast* is a cooldown,
because no request was made. A slow one is a real failure.
