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
