# Cortex packaging (deb / rpm)

The deb and rpm packages built from this directory install:

- /usr/local/bin/cortex -- the Cortex binary.
- /etc/cortex/cortex.yaml -- a hardened default configuration shipped
  from packaging/config/cortex.yaml. It binds HTTP and gRPC to
  127.0.0.1, sets auth_enabled true, and uses backend filesystem for
  blocks storage (no third-party S3 bucket).
- /usr/share/doc/cortex/examples/single-process-config.yaml -- the
  original single-process development/demo config from
  docs/configuration/single-process-config-blocks.yaml. It is shipped
  as a non-active sample only. Do not point CONFIG_FILE at it on a
  production host: it disables auth, binds 0.0.0.0, and lists a global
  S3 bucket name that this project does not own.
- /etc/default/cortex (deb) and /etc/sysconfig/cortex (rpm) -- the
  environment file read by the unit. CONFIG_FILE points at
  /etc/cortex/cortex.yaml.
- /etc/systemd/system/cortex.service -- the systemd unit.

## Required operator steps before exposing the service

Cortex authenticates nothing on its own: when auth_enabled is true,
it only requires that an X-Scope-OrgID header be present on every
request (any value is accepted). This is documented in
docs/guides/authentication-and-authorisation.md. In addition, several
admin endpoints (/config, /ingester/flush, /ingester/shutdown,
/distributor/all_user_stats, the various ring handlers) are
registered with auth=false and are therefore reachable regardless of
the auth_enabled setting.

Before exposing TCP/9009 (HTTP) or TCP/9095 (gRPC) beyond localhost you
must:

1. Deploy an authenticating reverse proxy (nginx with auth_basic or
   mTLS, oauth2-proxy, an API gateway, etc.) in front of Cortex. The
   proxy is responsible for authenticating the caller and setting the
   X-Scope-OrgID header on their behalf.
2. Only then widen server.http_listen_address and
   server.grpc_listen_address in /etc/cortex/cortex.yaml to a
   routable address, or point the proxy at 127.0.0.1:9009 and leave
   the Cortex listeners on loopback.
3. Block direct access to the Cortex ports from outside the host.
   Example firewalld rules can be found in your distribution docs; the
   simplest approach is to keep the default loopback bind in
   cortex.yaml and let the kernel enforce the boundary.
4. If you want systemd to enforce "localhost only" regardless of the
   config file, uncomment the IPAddressDeny and IPAddressAllow lines
   in /etc/systemd/system/cortex.service.

## Blocks storage default

The hardened config uses backend filesystem with
dir /var/lib/cortex/blocks and tsdb.dir /var/lib/cortex/tsdb. The
Cortex service user (User=cortex) owns /var/lib/cortex. Do not
re-introduce backend s3 with bucket_name cortex: that bucket name is
in AWS's global namespace and is not controlled by the Cortex
project. If you want remote object storage, set bucket_name to a
bucket you own, and provide credentials via your platform's standard
mechanisms.
