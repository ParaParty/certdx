# Quickstart

Run a single certdx server that issues a wildcard certificate from Let's
Encrypt via Cloudflare DNS-01, and a single client that writes the
certificate to disk and reloads nginx. Roughly five minutes once the
prerequisites are in place.

**You will need**

- A domain you control (`example.com` in this guide).
- Cloudflare DNS for that domain, plus an API token with `Zone:DNS:Edit`.
- Two Linux hosts (or one host running both daemons): one for the server,
  one for the client. The server host needs a public DNS name (here
  `certdx.example.com`) and an open inbound port.
- A release archive for your platform (`certdx_<os>_<arch>.tar.gz`) from
  the GitHub releases page.

If any option below is unclear, jump to the relevant reference:
[setup.md](setup.md), [server.md](server.md), [client.md](client.md).

## 1. Install

On each host (server and client), download the release archive for your
platform from the project's GitHub releases page, unpack it, and move the
resulting directory to `/opt/certdx`:

```sh
tar -xzf certdx_linux_amd64.tar.gz
sudo mv certdx_linux_amd64 /opt/certdx
```

`/opt/certdx` now contains:

```
/opt/certdx/
├── certdx_server
├── certdx_client
├── certdx_tools
├── config/
├── systemd-service/
└── LICENSE
```

Install the systemd unit you need on each host:

```sh
# server host
sudo cp /opt/certdx/systemd-service/certdx-server.service /etc/systemd/system/

# client host
sudo cp /opt/certdx/systemd-service/certdx-client.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## 2. Configure the server

Edit `/opt/certdx/config/server_config.toml` to look like:

```toml
[ACME]
email = "ops@example.com"
provider = "r3"
challengeType = "dns"
allowedDomains = ["example.com"]

[DnsProvider]
type = "cloudflare"
authToken = "<cloudflare api token>"
zoneToken = "<cloudflare api token>"

[HttpServer]
enabled = true
listen = ":19198"
apiPath = "/certdx"
authMethod = "token"
secure = true
names = ["certdx.example.com"]
token = "<a long random string>"
```

Make sure `certdx.example.com` resolves to this host and TCP `:19198` is
reachable from clients. The server obtains its own TLS certificate from
Let's Encrypt for that name on first start.

Start it:

```sh
sudo systemctl enable --now certdx-server
journalctl -u certdx-server -f
```

## 3. Configure the client

On the client host, create the output directory and edit
`/opt/certdx/config/client_config.toml`:

```sh
sudo mkdir -p /etc/ssl/certdx
```

```toml
[Common]
mode = "http"

[Http.MainServer]
url = "https://certdx.example.com:19198/certdx"
authMethod = "token"
token = "<same token as the server>"

[[Certifications]]
name = "wildcard-example"
savePath = "/etc/ssl/certdx"
domains = ["*.example.com", "example.com"]
reloadCommand = "systemctl reload nginx"
```

Start it:

```sh
sudo systemctl enable --now certdx-client
journalctl -u certdx-client -f
```

## 4. Verify

After the first issuance you should see:

```
/etc/ssl/certdx/wildcard-example.pem
/etc/ssl/certdx/wildcard-example.key
```

Point nginx (or whatever you use) at those paths. The client overwrites
them and runs `reloadCommand` whenever the server returns a renewed
certificate — no further action is needed.

## Where to go next

- Replace the bearer token with mTLS: [setup.md § mTLS](setup.md#mtls).
- Inspect what the server has cached: `certdx_tools show-certs`
  ([tools.md](tools.md#show-certs)).
