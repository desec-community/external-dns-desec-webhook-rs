# Deployment

## Shape

A sidecar in external-dns's own pod, on loopback.

The provider endpoints have **no authentication**. Binding them to the pod network grants DNS
write access for your zones to anything that can reach the port. The webhook warns at startup if
`--listen` is not a loopback address, and the default is `127.0.0.1:8888`.

Ports:

| Port | Bind | Endpoints |
| --- | --- | --- |
| 8888 | `127.0.0.1` | `/`, `/records`, `/adjustendpoints` |
| 8080 | `0.0.0.0` | `/healthz`, `/readyz`, `/metrics` |

## The token

```console
$ kubectl -n external-dns create secret generic desec-credentials \
    --from-literal=token=YOUR_DESEC_TOKEN
```

Prefer `DESEC_TOKEN_FILE` over `DESEC_TOKEN`: an environment variable shows up in
`kubectl describe pod` and is inherited by anything the process spawns. A trailing newline in the
file is trimmed, since deSEC answers 401 for a token with one.

Scope the token in deSEC to the zones you manage. This provider never creates or deletes zones,
so it needs neither `perm_create_domain` nor `perm_delete_domain`.

## Helm values

```yaml
provider:
  name: webhook
  webhook:
    image:
      repository: ghcr.io/desec-community/external-dns-desec-webhook-rs
      tag: v0.0.1
    env:
      - name: DESEC_TOKEN_FILE
        value: /etc/desec/token
      - name: DESEC_DOMAIN_FILTER
        value: example.com
    extraVolumeMounts:
      - name: desec-credentials
        mountPath: /etc/desec
        readOnly: true
    livenessProbe:
      httpGet:
        path: /healthz
        port: http-webhook-metrics
      periodSeconds: 10
      timeoutSeconds: 3
      # Generous on purpose: a deSEC throttle window must not restart the pod, because a
      # restart discards the rate limiter's in-memory state and makes the throttling worse.
      failureThreshold: 6
    readinessProbe:
      httpGet:
        path: /readyz
        port: http-webhook-metrics
      periodSeconds: 30
      failureThreshold: 6
    resources:
      requests:
        cpu: 10m
        memory: 32Mi
      limits:
        memory: 128Mi

extraVolumes:
  - name: desec-credentials
    secret:
      secretName: desec-credentials
      items:
        - key: token
          path: token

# Required. See docs/protocol.md for why the default prefix cannot work for a zone apex.
extraArgs:
  - --txt-prefix=externaldns-%{record_type}.

policy: sync
registry: txt
txtOwnerID: my-cluster
domainFilters:
  - example.com
```

Do **not** add a `startupProbe` on `/readyz` with a short `failureThreshold`. If deSEC is
throttling at startup the snapshot will not populate, the probe will fail, and the pod will
restart-loop — burning the daily budget on repeated zone lists. If you want one, point it at
`/healthz` with `failureThreshold: 30`.

## Migrating from the Go provider

Names changed, and two of the old ones did not work as documented anyway: its README said
`WEBHOOK_ADDRESS` and `WEBHOOK_PORT` while its `envconfig` read `WEBHOOK_WEBHOOKADDRESS` and
`WEBHOOK_WEBHOOKPORT`.

| Old | New | Note |
| --- | --- | --- |
| `WEBHOOK_APITOKEN` | `DESEC_TOKEN`, or `DESEC_TOKEN_FILE` | |
| `WEBHOOK_DOMAINFILTERS` | `DESEC_DOMAIN_FILTER` | still comma-separated, still required |
| `WEBHOOK_DEFAULTTTL` | *(gone)* | the zone's own `minimum_ttl` is read from the API |
| `WEBHOOK_WEBHOOKADDRESS` + `WEBHOOK_WEBHOOKPORT` | `WEBHOOK_LISTEN` | one `host:port` |
| `WEBHOOK_HEALTHADDRESS` + `WEBHOOK_HEALTHPORT` | `WEBHOOK_ADMIN_LISTEN` | one `host:port` |
| `WEBHOOK_DRYRUN` | `WEBHOOK_DRY_RUN` | |
| `WEBHOOK_LOGLEVEL` | `RUST_LOG` | e.g. `external_dns_desec_webhook=debug` |

Two external-dns flags you can drop:

- **`--min-ttl=1h`** was a workaround for the provider not normalizing TTLs where external-dns
  could see it. `/adjustendpoints` now clamps against each zone's real minimum.
- **`--webhook-provider-read-timeout=30s`** was a workaround for the provider blocking while
  throttled. Handlers now answer inside the default 5s+10s budget, with a 503 rather than a hang.
  The one case that may still want a longer timeout is a first refresh over a very large number
  of zones.

`WEBHOOK_DEFAULTTTL` has no replacement because it was the wrong idea: the useful value is the
zone's own `minimum_ttl`, which deSEC reports per zone and which is not always 3600.
