# Breaking changes in v0.7.0

v0.7.0 reshapes the client configuration around **update actions**:

1. The `[[Certifications]]` section is renamed to **`[[Certificate]]`**.
2. `savePath` and `reloadCommand` move out of the certificate into a
   **`[[Certificate.UpdateAction]]` of `type = "file"`**.
3. The Tencent Cloud and Kubernetes updaters are no longer
   `certdx_tools` sub-commands. They are update actions of
   `certdx_client` and run continuously instead of once per invocation.

Every client config must be updated. There is no compatibility shim.

---

## 1. `[[Certifications]]` → `[[Certificate]]`

### Before

```toml
[[Certifications]]
name = "wildcard-example"
savePath = "/etc/ssl/certdx"
domains = ["*.example.com", "example.com"]
reloadCommand = "systemctl reload nginx"
```

### After

```toml
[[Certificate]]
name = "wildcard-example"
domains = ["*.example.com", "example.com"]

[[Certificate.UpdateAction]]
type = "file"
savePath = "/etc/ssl/certdx"
reloadCommand = "systemctl reload nginx"
```

Each certificate now needs at least one update action. A certificate
with none fails validation with
`certificate <name> has no update action configured`.

Every `[[Certificate.UpdateAction]]` binds to the `[[Certificate]]`
above it, so keep one certificate's actions together.

### Library API

- `config.ClientCertification` → `config.ClientCertificate`.
- `ClientConfig.Certifications` → `ClientConfig.Certificates`.
- `ClientCertificate.SavePath` / `.ReloadCommand` are gone; they live on
  `config.FileAction`, reachable via `ClientCertificate.FileAction()`.
- `ClientCertificate.GetFullChainAndKeyPath()` →
  `FileAction.GetFullChainAndKeyPath(certName)`.
- `config.WithAcceptEmptyCertificateSavePath` →
  `config.WithAcceptEmptyUpdateActions`.
- `CertDXClientDaemon.ClientInit()` now returns an `error`.
- Config loaded outside `LoadConfigurationAndValidate` must call
  `ClientConfig.DecodeActions(md)` with the metadata from
  `cli.LoadTOMLMeta` before `Validate`.
- Validation wording: `no certification configured` → `no certificate
  configured`, `wrong certification configuration for <name>` → `wrong
  certificate configuration for <name>`.

## 2. Kubernetes updater

`certdx_tools kubernetes-certificate-updater` (aliases `k8s-update`,
`k8s-certificate-updater`) is **removed**. Configure a `kubernetes`
update action on `certdx_client` instead.

### Before

`config/client_k8s.toml`, run as a Job or CronJob:

```toml
[[Certifications]]
name = "domainsToWatch"
domains = ["*.example.com", "*.mm.example.com"]
```

```sh
certdx_tools kubernetes-certificate-updater -c client_k8s.toml --k8sConf ~/.kube/config
```

### After

```toml
[[Profile.Kubernetes]]
name = "cluster-a"
# empty means in-cluster, then $KUBECONFIG, then ~/.kube/config
kubeConfig = ""

[[Certificate]]
name = "domainsToWatch"
domains = ["*.example.com", "*.mm.example.com"]

[[Certificate.UpdateAction]]
type = "kubernetes"
profile = "cluster-a"
```

```sh
certdx_client -c client.toml
```

Behaviour changes:

- **Run it as a Deployment, not a CronJob.** The client is long-running.
  `config/kubernetes/` ships an example Deployment.
- Annotated secrets are re-listed on **every renewal** instead of once at
  start-up, so secrets created later are picked up without a restart.
- The ten-minute completion deadline is gone; there is nothing to
  complete.
- `--k8sConf` becomes `kubeConfig` on the profile.
- Required RBAC is unchanged: cluster-wide `list`, `get`, `update` on
  secrets.
- The secret annotation `party.para.certdx/domains` is unchanged.

## 3. Tencent Cloud updater

`certdx_tools tencent-cloud-certificate-updater` (aliases `tx-update`,
`tencent-cloud-certificates-updater`) is **removed**. Configure a
`tencentCloud` update action instead.

### Before

`config/client_tencentcloud_certificate_updater.toml`, run from cron:

```toml
[Authorization]
secretID = "tencent cloud secret id"
secretKey = "tencent cloud secret key"

[[Certifications]]
name = "certificate name to display"
domains = ["*.example.com"]
resourceTypes = ["teo"]
resourceTypesRegions = [{ resourceType = "", regions = [] }]
```

### After

```toml
[[Profile.TencentCloud]]
name = "prod"
secretID = "tencent cloud secret id"
secretKey = "tencent cloud secret key"

[[Certificate]]
name = "certificate name to display"
domains = ["*.example.com"]

[[Certificate.UpdateAction]]
type = "tencentCloud"
profile = "prod"
resourceTypes = ["teo"]
```

Behaviour changes:

- **No cron entry.** The action runs when the server delivers a renewed
  certificate.
- The expiring-certificate filter is gone. Discovery runs on every update
  and picks the newest uploaded certificate whose SANs equal the
  certificate's `domains`.
- `[Authorization]` becomes a named `[[Profile.TencentCloud]]`, so several
  accounts can be used from one config.
- `resourceTypes` is validated at load against `clb`, `cdn`, `waf`,
  `live`, `vod`, `ddos`, `tke`, `apigateway`, `tcb`, `teo`.
- Every `resourceTypesRegions` entry must name a `resourceType` that also
  appears in `resourceTypes`. The old placeholder
  `{ resourceType = "", regions = [] }` is now rejected — delete the line
  if you have no region filter.
- The single config file is no longer parsed twice into two schemas.

## 4. Removed sample configs

`config/client_k8s.toml` and
`config/client_tencentcloud_certificate_updater.toml` are deleted. Both
are commented examples in `config/client_config_full.toml` now.

## 5. Container image

The published image entrypoint changes from `certdx_tools` to
`certdx_client`. Drop the sub-command argument:

```diff
 args:
-  - kubernetes-certificate-updater
   - --conf=/etc/certdx/client.toml
```
