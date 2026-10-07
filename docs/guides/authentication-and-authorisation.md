---
title: "Authentication and Authorisation"
linkTitle: "Authentication and Authorisation"
weight: 10
slug: auth
---

All Cortex components take the tenant ID from a header `X-Scope-OrgID`
on each request. A tenant (also called "user" or "org") is the owner of
a set of series written to and queried from Cortex. All Cortex components
trust this value completely: if you need to protect your Cortex installation
from accidental or malicious calls then you must add an additional layer
of protection.

Typically this means you run Cortex behind a reverse proxy, and you must
ensure that all callers, both machines sending data over the `remote_write`
interface and humans sending queries from GUIs, supply credentials
which identify them and confirm they are authorised. When configuring the
`remote_write` API in Prometheus, the user and password fields of http Basic
auth, or Bearer token, can be used to convey the tenant ID and/or credentials.
See the [Cortex-Tenant](#cortex-tenant) section below for one way to solve this.

In trusted environments, Prometheus can send the `X-Scope-OrgID` header itself
by configuring the `headers` field in its [`remote_write` configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#remote_write):
```
remote_write:
  - url: http://<cortex>/prometheus/api/v1/push
    headers:
      X-Scope-OrgID: <org>
```

To disable the multi-tenant functionality, you can pass the argument
`-auth.enabled=false` to every Cortex component, which will set the OrgID
to the string `fake` for every request.

Note that the tenant ID that is used to write the series to the datastore
should be the same as the one you use to query the data. If they don't match
you won't see any data. As of now, you can't see series from other tenants.

For more information regarding the tenant ID limits, refer to: [Tenant ID limitations](./limitations.md#tenant-id-naming)

### Cortex-Tenant

One way to add `X-Scope-OrgID` to Prometheus requests is to use a [cortex-tenant](https://github.com/blind-oracle/cortex-tenant)
proxy which is able to extract the tenant ID from Prometheus labels.

It can be placed between Prometheus and Cortex and will search for a predefined
label and use its value as `X-Scope-OrgID` header when proxying the timeseries to Cortex.

This can help to run Cortex in a trusted environment where you want to separate your metrics
into distinct namespaces by some criteria (e.g. teams, applications, etc).

Be advised that **cortex-tenant** is a third-party community project and it's not maintained by Cortex team.

### Destructive admin endpoints and ring mutations

Cortex exposes a small set of destructive operator endpoints on the
ordinary HTTP listener. These must never be reachable from untrusted
callers, because a single unauthenticated request can take an ingester
offline, trigger cross-tenant compaction/upload, or remove instances
from the shared ring KV cluster-wide:

- `POST /ingester/flush` and the legacy alias `POST /flush`
- `POST /ingester/shutdown` and the legacy alias `POST /shutdown`
- `POST <component>/ring` with a `forget=<instance-id>` form value, on
  every ring status page (`/ingester/ring`, `/ring`, `/distributor/ring`,
  `/ruler/ring`, `/ruler_ring`, `/store-gateway/ring`, `/compactor/ring`,
  `/multitenant_alertmanager/ring`).

Starting with this release, destructive endpoints are **disabled by
default**:

- `/ingester/flush`, `/ingester/shutdown`, `/flush`, `/shutdown` are not
  registered unless `-api.enable-dangerous-ops=true` is set, and when
  enabled only `POST` is accepted (plain browser `GET` navigation can no
  longer trigger them).
- `POST` (forget) on every ring page is rejected with `403 Forbidden`
  unless `-ring.allow-mutations-via-http=true` is set. Even when enabled
  the handler requires the request's `Origin`/`Referer` to match the
  request `Host` so a cross-site browser form cannot drive the ring
  mutation.
- When the per-tenant `/ingester/flush` endpoint is called with an
  authenticated tenant in the request context, the handler now ignores
  cross-tenant values of the `tenant=` form parameter and only acts on
  the authenticated tenant.

As defence in depth your authenticating reverse proxy **must** deny the
above paths and methods unless the caller is an authorised operator.
An example deny list:

```
location ~ ^/(ingester/flush|ingester/shutdown|flush|shutdown)$ { return 403; }
location ~ ^/(ingester|distributor|ruler|ruler_ring|store-gateway|compactor|multitenant_alertmanager)/ring$ {
    if ($request_method = POST) { return 403; }
}
```
