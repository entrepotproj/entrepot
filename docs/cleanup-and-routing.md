# Cleanup policies, routing rules and dependency confusion

## Cleanup policies

A cleanup policy deletes components that match **all** of its set criteria.
Repositories opt in by listing policies in `cleanup.policies`.

| Criterion | Meaning |
|---|---|
| `publishedOlderThanDays` | the component was published (or first cached) more than N days ago |
| `lastDownloadedOlderThanDays` | the component has not been downloaded for N days. Never-downloaded components count from their publish date |
| `nameRegex` / `versionRegex` | regular expressions over the name / version |
| `prereleaseOnly` | only pre-releases. npm, Helm and Docker use SemVer pre-release; PyPI uses PEP 440 `a`, `b`, `rc` and `dev`; Apt and Yum use a `~` or alpha/beta/rc markers |
| `keepLatest` | always keep the N newest versions of each name. Versions are ordered when every version parses in the format's scheme, otherwise by publish date |
| `untaggedOlderThanDays` | Docker: delete untagged manifests older than N days, plus layer links no remaining manifest references |

```bash
curl -H "Authorization: Bearer $ADMIN" -X POST $E/api/v1/cleanup-policies -d '{
  "name": "prune-snapshots", "format": "npm",
  "criteria": {"prereleaseOnly": true, "publishedOlderThanDays": 30, "keepLatest": 5}
}'
# What would it delete?
curl -H "Authorization: Bearer $ADMIN" -X POST "$E/api/v1/cleanup-policies/prune-snapshots/preview?repository=npm-internal"
# Run a repository's policies now (dryRun=true for a preview)
curl -H "Authorization: Bearer $ADMIN" -X POST "$E/api/v1/repositories/npm-internal/cleanup?dryRun=false"
```

* **Schedule.** Policies run every `cleanup.interval` (default `24h`). A
  cluster-wide lock ensures only one replica runs them, and each run is
  audited (`cleanup.run`).
* **What gets deleted.** Component assets are deleted, then format metadata is
  regenerated (npm packuments, PyPI indexes, Apt `Packages`/`Release`, Yum
  repodata, Helm `index.yaml`). Freed blobs are garbage-collected afterwards.
* **Proxies.** Cleanup only evicts cached components; anything still needed is
  fetched again on demand.
* **Groups** are skipped.
* **In-use policies.** A policy that repositories use can't be deleted (`409`
  lists them).

## Routing rules

A routing rule restricts what a **proxy** repository may fetch from its
upstream. A rule has a mode and a list of regular expressions:

* `block`: matching requests never go upstream;
* `allow`: only matching requests go upstream.

Rules are matched against a format-aware subject:

| Format | Subject |
|---|---|
| npm | package name (`@acme/widgets`) |
| PyPI | normalised project name (`acme-utils`) |
| Docker | upstream image name (`library/alpine`) |
| Helm | chart name; blocked charts are also filtered out of the proxied `index.yaml` |
| others | the request path |

```bash
curl -H "Authorization: Bearer $ADMIN" -X POST $E/api/v1/routing-rules -d '{
  "name": "no-internal-names", "mode": "block", "matchers": ["^@acme/", "^acme-"]
}'
curl -H "Authorization: Bearer $ADMIN" -X POST $E/api/v1/routing-rules/no-internal-names/test -d '{"path":"@acme/widgets"}'
# then set "proxy": {"routingRule": "no-internal-names", ...} on npm-proxy / pypi-proxy
```

Blocked requests look like `404` to clients. A rule a proxy uses can't be
deleted. Content cached before a rule was added keeps being served until it
goes stale.

## Dependency confusion

Dependency confusion is when an attacker publishes a public package with the
same name as one of your internal packages and a higher version, so that
builds resolving through a group pick up the public one. Entrepot has two
defences, and you should use both:

1. **Groups prefer hosted packages (on by default).** For npm, PyPI and Helm
   groups, if any hosted member has a package name, proxy members never
   contribute versions or files for that name. Set `group.preferHosted:
   false` only if you deliberately mix internal and public versions of the
   same name.
2. **Routing rules** on the proxies block your internal namespaces outright,
   for example `^@acme/` for npm scopes or `^acme-` for PyPI prefixes. This
   also covers names that don't exist internally yet.

npm scopes you own (`@acme`) are the strongest protection; register them on
npmjs.com even if you never publish there.
