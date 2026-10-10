# Breaking changes in v0.8.0

## Stricter server config validation

`certdx_server` now rejects these configs at startup instead of failing
later at runtime:

- `certLifeTime` or `renewTimeLeft` that is zero or negative.
- With `provider = "google"` or `"googletest"`, `certLifeTime + renewTimeLeft`
  longer than 90 days. The CA would refuse such an order anyway.
- A `[DnsProvider].nameservers` entry that is not `host` or `host:port`, for
  example a URL such as `udp://8.8.8.8`, an empty entry, or an invalid port.
- `[HttpProvider.S3]` without `bucket`, `url`, `accessKeyId` or
  `accessKeySecret`.

## Stricter client config validation

`certdx_client` now rejects certificates that would overwrite each other:

- Two `[[Certificate]]` entries with the same domain set, compared ignoring
  case, order, duplicates and a trailing dot. Before, the second silently
  replaced the first and the first one's update actions never ran. Merge
  them into one `[[Certificate]]` with all of their update actions.
- In `mode = "grpc"`, two certificates with the same `name`. HTTP mode still
  allows a repeated name.
- Two `type = "file"` update actions that write the same
  `<savePath>/<name>.pem`, in the same certificate or in different ones.

A certificate whose domains are all blank (`""` or `"."`) is also rejected,
and the Caddy plugin refuses to start with such a certificate.
