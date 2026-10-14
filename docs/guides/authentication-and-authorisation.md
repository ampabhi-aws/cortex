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

### Admin (cross-tenant) HTTP endpoints

A small number of Cortex HTTP endpoints return or mutate data that spans
every tenant (the full list of tenants, each tenant's raw Alertmanager
configuration -- which may embed receiver credentials -- every tenant's
rule groups, per-tenant limit overrides, HA tracker state, and the raw
gossiped memberlist KV). These are operator-only endpoints and **must not
be exposed to end users**:

* `/multitenant_alertmanager/configs`
* `/ruler/rule_groups`
* `/distributor/all_user_stats` (and the legacy `/all_user_stats` alias)
* `/distributor/ha_tracker` (and the legacy `/ha-tracker` alias)
* `/runtime_config`
* `/memberlist`

Cortex registers these endpoints through `API.RegisterAdminRoute`, which
wraps the handler with `Config.HTTPAdminMiddleware`. When no admin
middleware is configured, the API falls back to the tenant auth middleware
so the endpoints at least require a valid `X-Scope-OrgID` header rather
than being reachable with no identity at all. Operators are strongly
encouraged to:

1. Inject a stricter middleware into `Config.HTTPAdminMiddleware` -- for
   example one that validates a shared operator bearer token or a source-IP
   allowlist -- so that only operators can reach these paths; and/or
2. Front Cortex with a reverse proxy that denies the paths above by default
   and only allows them through the operator plane (a separate hostname,
   port or network).

### Cortex-Tenant

One way to add `X-Scope-OrgID` to Prometheus requests is to use a [cortex-tenant](https://github.com/blind-oracle/cortex-tenant)
proxy which is able to extract the tenant ID from Prometheus labels.

It can be placed between Prometheus and Cortex and will search for a predefined
label and use its value as `X-Scope-OrgID` header when proxying the timeseries to Cortex.

This can help to run Cortex in a trusted environment where you want to separate your metrics
into distinct namespaces by some criteria (e.g. teams, applications, etc).

Be advised that **cortex-tenant** is a third-party community project and it's not maintained by Cortex team.
