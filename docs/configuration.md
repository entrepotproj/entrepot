# Configuration

Entrepot reads a YAML file (`-config` flag or `ENTREPOT_CONFIG`) and then
applies environment overrides. Every key can be overridden with `ENTREPOT_`
followed by its upper-cased path joined with `_`:

| Key | Env | Default |
|---|---|---|
| `server.addr` | `ENTREPOT_SERVER_ADDR` | `:8080` |
| `server.baseURL` | `ENTREPOT_SERVER_BASEURL` | derived from each request |
| `server.trustForwardedHeaders` | `ENTREPOT_SERVER_TRUSTFORWARDEDHEADERS` | `false` |
| `database.url` | `ENTREPOT_DATABASE_URL` (`_FILE` supported) | local dev URL |
| `database.maxConns` | `ENTREPOT_DATABASE_MAXCONNS` | `20` |
| `database.autoMigrate` | `ENTREPOT_DATABASE_AUTOMIGRATE` | `true` |
| `auth.sessionSecret` | `ENTREPOT_AUTH_SESSIONSECRET` (`_FILE`) | **required**, ≥ 32 bytes, same on all replicas |
| `auth.sessionTTL` | `ENTREPOT_AUTH_SESSIONTTL` | `12h` |
| `auth.bootstrapToken` | `ENTREPOT_AUTH_BOOTSTRAPTOKEN` (`_FILE`) | disabled |
| `auth.adminGroups` / `auth.adminUsers` | comma-separated | none |
| `auth.anonymousAccess` | `ENTREPOT_AUTH_ANONYMOUSACCESS` | `true` (only affects repos with `anonymousRead`) |
| `auth.oidc.*` | `ENTREPOT_AUTH_OIDC_ENABLED`, `…_ISSUERURL`, `…_CLIENTID`, `…_CLIENTSECRET` (`_FILE`), `…_GROUPSCLAIM`, … | disabled |
| `auth.gitlab` | `ENTREPOT_AUTH_GITLAB` (JSON/YAML list) | none |
| `storage.allowedRoots` | `ENTREPOT_STORAGE_ALLOWEDROOTS` | `/data` |
| `storage.tempDir` | `ENTREPOT_STORAGE_TEMPDIR` | OS temp dir |
| `proxy.timeout` | `ENTREPOT_PROXY_TIMEOUT` | `60s` (time to response headers) |
| `blobStores` | `ENTREPOT_BLOBSTORES` (JSON/YAML list) | none (a `default` file store is created when no stores exist) |
| `log.level` / `log.format` | `ENTREPOT_LOG_LEVEL` / `ENTREPOT_LOG_FORMAT` | `info` / `json` |
| `secrets.key` | `ENTREPOT_SECRETS_KEY` (`_FILE`) | derived from `auth.sessionSecret`. Encrypts secrets stored in Postgres; same on all replicas |
| `secrets.previousKeys` | comma-separated | none. Old keys that can still decrypt during a rotation; values are re-encrypted with the current key at startup |
| `scan.workers` | `ENTREPOT_SCAN_WORKERS` | `2` in-process scan workers (`0` when a separate `entrepot scan-worker` runs them) |
| `scan.workDir` / `scan.jobTimeout` / `scan.pollInterval` | `ENTREPOT_SCAN_*` | temp dir / `15m` / `2s` |
| `cleanup.interval` | `ENTREPOT_CLEANUP_INTERVAL` | `24h` (`0` disables scheduled cleanup) |
| `auth.gitlab[].api` | — | `{url, token \| tokenEnv \| tokenFile}`: a GitLab API token for scan feedback |

Validate a configuration with `entrepot check-config -config file.yaml`. It
prints the effective configuration with secrets redacted.

## Full example

```yaml
server:
  addr: ":8080"
  baseURL: https://entrepot.example.com
  trustForwardedHeaders: true
database:
  url: postgres://entrepot:secret@db:5432/entrepot?sslmode=require
auth:
  sessionSecret: <48 random characters>
  adminGroups: [entrepot-admins]
  oidc:
    enabled: true
    issuerURL: https://keycloak.example.com/realms/platform
    clientID: entrepot
    clientSecret: <secret>
    groupsClaim: groups
  gitlab:
    - name: gitlab
      issuerURL: https://gitlab.example.com
storage:
  allowedRoots: [/data]
blobStores:
  - {name: default, type: file, path: /data/default}
  - name: s3
    type: s3
    s3: {bucket: my-artifacts, region: eu-west-2, redirectDownloads: "true"}
```

## Repository settings (API / UI)

| Field | Meaning |
|---|---|
| `format` | `raw`, `pypi`, `npm`, `docker`, `apt`, `yum`, `helm` (immutable) |
| `kind` | `hosted`, `proxy`, `group` (immutable) |
| `blobStore` | store for this repository's content (immutable) |
| `online` | offline proxies serve only cached content |
| `anonymousRead` | allow unauthenticated reads |
| `hosted.allowRedeploy` | allow overwriting existing files/versions (default false) |
| `proxy.remoteUrl` | upstream URL |
| `proxy.username` / `proxy.password` | upstream credentials (sent only to the upstream host) |
| `proxy.metadataTtlSeconds` | cache time for indexes/metadata/tags (default 3600) |
| `proxy.contentTtlSeconds` | cache time for artifacts (default 0 = immutable) |
| `proxy.negativeCacheTtlSeconds` | cache time for upstream 404s (default 300, -1 disables) |
| `group.members` | ordered member repositories of the same format |
| `group.preferHosted` | npm/PyPI/Helm: never take a name from proxies if a hosted member has it (default true) |
| `proxy.routingRule` | routing rule restricting what is fetched upstream |
| `hosted.apt.distributions` | Apt: `[{name, components, architectures, origin, label}]` (default `stable`/`main`) |
| `hosted.yum.repodataDepth` | Yum: directory depth for repodata (default 0) |
| `scan` | `{scanners, mode: off\|warn\|quarantine, severityThreshold, onUpload, onProxyFetch, blockUntilScanned, distro}`. See [scanning](scanning.md) |
| `cleanup.policies` | cleanup policies to apply. See [cleanup](cleanup-and-routing.md) |
