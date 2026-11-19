# Architecture

```
                  ┌──────────────────────────── entrepot (Go binary, N replicas) ───────────────────────────┐
 browser ───────► │  /            React UI (embedded)                                                       │
                  │  /auth/*      OIDC login (code + PKCE), token login, logout                              │
 terraform,       │  /api/v1/*    management API  ◄── api/openapi.yaml (spec-first, oapi-codegen)          │
 scripts ───────► │  /api/docs    Swagger UI                                                                 │
                  │                                                                                          │
 pip, twine,      │  /repository/{repo}/…  ─► format.Registry ─► raw │ pypi │ npm   (hosted/proxy/group)    │
 npm, curl ─────► │  /v2/…, /v2/token      ─► docker (OCI distribution + token auth)                         │
 docker, crane    │                                                                                          │
                  │  auth.Authenticator ─► authz.Authorizer (roles × bindings × repo globs)                 │
                  │  repo.Service (assets, components, serving) ─► proxy.Cache (TTL, singleflight, neg. cache)│
                  │  storage.Registry ─► BlobStore drivers: file (PVC/EBS/EFS) │ s3                          │
                  └───────────────┬───────────────────────────────────────────────┬──────────────────────────┘
                                  │ metadata                                       │ content (sha256-addressed)
                               Postgres                                  volumes / S3 buckets
```

## Request flow

1. **Authentication**: `auth.Authenticator` turns the request's credentials
   into a `Principal`: a session cookie, an `ent_` API token, an OIDC JWT, a
   GitLab id_token, a registry token or the bootstrap token. Verified bearer
   JWTs are cached briefly.
2. **Routing**: `/repository/{repo}/…` loads the repository (cached for 5s)
   and dispatches to its format handler. Docker mounts its own `/v2/` routes.
3. **Authorization**: each handler maps the operation to an action (read,
   write or delete) and asks `authz.Authorizer`. The authorizer evaluates the
   role bindings (also cached for 5s and invalidated on change) against the
   principal's username, groups and matched GitLab policies.
4. **Hosted writes**: `repo.Service.Put` streams the body into the
   repository's blob store, hashing as it goes. It then records the asset (and
   optionally its component) in one transaction that also maintains blob
   reference counts.
5. **Proxy reads**: `proxy.Cache.Get` serves fresh cached assets. Stale ones
   are revalidated with conditional requests. Misses are fetched once
   (singleflight, detached from the client's cancellation), stored, then
   served. Upstream 404s are cached negatively. If the upstream fails, stale
   content is served.
6. **Group reads** try the members in order and merge indexes (PyPI simple
   pages, npm packuments).
7. **Serving** uses `http.ServeContent` (Range, If-None-Match, HEAD). S3 stores
   can redirect large downloads to presigned URLs.

## Data model

| Table | Purpose |
|---|---|
| `blob_stores` | store name, type (`file`/`s3`) and config |
| `repositories` | name, format, kind, blob store, flags, typed config (proxy/hosted/group) |
| `blobs` | (store, digest) → size and reference count, for dedup and GC |
| `components` | logical package versions (name + version) per repository |
| `assets` | files in a repository: path → digest, content type, attrs, cached/downloaded timestamps |
| `users`, `api_tokens` | OIDC users and service accounts; hashed tokens with scopes and expiry |
| `roles`, `role_bindings`, `gitlab_trust_policies` | RBAC |
| `docker_uploads` | in-progress chunked blob uploads |
| `audit_events` | who did what, from where |

## Extending: adding a format

Implement `format.Handler` (`Name`, `Kinds`, `ServeHTTP`) using the shared
services in `format.Env` (repository service, proxy cache, authorizer, URL
helpers), and register it in `internal/app/app.go`. Optional interfaces:

* `format.Uploader` — generic API upload,
* `format.Validator` — validate repository configuration,
* `format.RootMounter` — routes outside `/repository/` (like Docker's `/v2/`),
* `format.ClientURLer` — the URL to show in client setup instructions.

## Scaling and HA

Pods are stateless. All shared state lives in Postgres and the blob stores,
and the caches (repositories, bindings, trust policies, verified tokens) hold
only a few seconds of data. Run several replicas behind the Service when the
blob stores are ReadWriteMany (EFS) or S3. Chunked Docker uploads keep their
chunks in the blob store's temp area, so consecutive PATCH requests can land
on different pods. Migrations take a Postgres advisory lock, so replicas can
start concurrently.
