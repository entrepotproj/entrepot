# Entrepot

**Entrepot** is a self-hosted package repository manager for Kubernetes —
host your own packages and proxy (pull-through cache) public registries,
behind single sign-on.

> *entrepôt* — a port where goods are stored and re-exported without duties.

| Format | Hosted | Proxy | Group | Native clients |
|---|:-:|:-:|:-:|---|
| Raw files | ✅ | ✅ | ✅ | curl, wget, anything HTTP |
| PyPI | ✅ | ✅ | ✅ | pip, twine, uv, poetry |
| npm | ✅ | ✅ | ✅ | npm, yarn, pnpm |
| Docker / OCI | ✅ | ✅ | ✅ | docker, podman, crane, helm (OCI) |
| Apt (signed) | ✅ | ✅ | | apt-get |
| Yum / RPM (signed) | ✅ | ✅ | | dnf, yum |
| Helm (HTTP) | ✅ | ✅ | ✅ | helm, helm cm-push |

**Highlights**

* **Proxy everything**: Docker Hub, ghcr.io, quay.io, GitLab registries,
  pypi.org, registry.npmjs.org or any HTTP server. Proxies revalidate with
  conditional requests, collapse concurrent misses, cache 404s, and keep
  serving cached content when the upstream is down.
* **Per-repository storage**: PVC, EBS (gp3), EFS or S3, all content-addressed
  and deduplicated.
* **OIDC from day one**: Keycloak (or any OIDC provider) login, group-based
  roles, bearer access tokens.
* **GitLab CI without secrets**: jobs authenticate with their `id_token`, and
  trust policies decide which projects, branches and environments may publish
  where.
* **API first**: a spec-first OpenAPI 3 API with Swagger UI at `/api/docs`, a
  generated Go client (`pkg/client`), and a Terraform provider planned for
  Phase 3.
* **Kubernetes-native**: one static binary, stateless pods, Postgres for
  metadata, a Helm chart, Prometheus metrics and health probes.
* **Vulnerability scanning**: Trivy, Grype or any scanner via a signed
  webhook. Scans run on upload, proxy fetch, on demand or on a schedule.
  Repositories can warn or **quarantine**, with waivers, and results are
  posted back to GitLab as commit statuses and MR notes.
* **Hygiene**: cleanup policies, routing rules, and groups that prefer hosted
  packages to defeat dependency confusion. Secrets are encrypted at rest.
* **Web UI**: browse, search, upload, manage repositories, tokens and access
  control.

## Quick start (docker compose)

```bash
docker compose -f deploy/compose/docker-compose.yaml up -d --build
open http://localhost:8080          # sign in with Keycloak: alice/alice (admin) or bob/bob
```

The compose stack starts Postgres, MinIO (an S3 blob store) and Keycloak, with
the realm, client and users pre-configured. The bootstrap admin token is
`dev-bootstrap-token`.

Create a few repositories:

```bash
E=http://localhost:8080; T=dev-bootstrap-token
api() { curl -fsS -H "Authorization: Bearer $T" -H 'Content-Type: application/json' "$@"; }
api -X POST $E/api/v1/repositories -d '{"name":"npm-proxy","format":"npm","kind":"proxy","blobStore":"default","anonymousRead":true,"proxy":{"remoteUrl":"https://registry.npmjs.org"}}'
api -X POST $E/api/v1/repositories -d '{"name":"pypi-proxy","format":"pypi","kind":"proxy","blobStore":"default","anonymousRead":true,"proxy":{"remoteUrl":"https://pypi.org"}}'
api -X POST $E/api/v1/repositories -d '{"name":"docker-hub","format":"docker","kind":"proxy","blobStore":"minio","anonymousRead":true,"proxy":{"remoteUrl":"https://registry-1.docker.io"}}'
api -X POST $E/api/v1/repositories -d '{"name":"files","format":"raw","kind":"hosted","blobStore":"default"}'
```

## Using it

See [docs/clients.md](docs/clients.md) for every client. In short:

```bash
# pip / twine
pip install --index-url http://localhost:8080/repository/pypi-proxy/simple/ requests
twine upload --repository-url http://localhost:8080/repository/pypi-internal/ -u token -p "$ENTREPOT_TOKEN" dist/*

# npm
npm config set registry http://localhost:8080/repository/npm-proxy/
npm config set //localhost:8080/repository/npm-internal/:_authToken "$ENTREPOT_TOKEN"

# docker (repository name is the first path segment)
docker pull localhost:8080/docker-hub/library/alpine:3.20
echo "$ENTREPOT_TOKEN" | docker login localhost:8080 -u token --password-stdin

# raw
curl -H "Authorization: Bearer $ENTREPOT_TOKEN" -T app.tar.gz http://localhost:8080/repository/files/releases/1.0/app.tar.gz
```

## Deploying to Kubernetes

```bash
helm install entrepot deploy/helm/entrepot \
  -f deploy/helm/entrepot/examples/eks-s3.yaml \
  --set baseURL=https://entrepot.example.com
```

Example values for [EBS](deploy/helm/entrepot/examples/eks-ebs.yaml),
[EFS](deploy/helm/entrepot/examples/eks-efs.yaml),
[S3 + IRSA](deploy/helm/entrepot/examples/eks-s3.yaml) and
[Keycloak + GitLab](deploy/helm/entrepot/examples/keycloak-gitlab.yaml)
are included. See [docs/storage.md](docs/storage.md) for the trade-offs.

## Documentation

* [Architecture](docs/architecture.md)
* [Configuration](docs/configuration.md)
* [Authentication & authorization](docs/authentication.md) — Keycloak, GitLab CI id_tokens, RBAC, tokens
* [Storage](docs/storage.md) — PVC / EBS / EFS / S3
* [Client setup](docs/clients.md)
* [Vulnerability scanning](docs/scanning.md)
* [Cleanup, routing & dependency confusion](docs/cleanup-and-routing.md)
* [Roadmap](docs/roadmap.md) — Terraform provider next

## Development

Requirements: Go 1.26+, Node 22+, Postgres 14+ (for integration tests).

```bash
make ui build          # build the React UI and the server (bin/entrepot)
make test              # unit + integration tests (needs Postgres; see TEST_DATABASE_URL in the Makefile)
make gen               # regenerate API server/client and UI types after editing api/openapi.yaml
make helm-lint
```

Layout:

```
cmd/entrepot/          server binary
api/openapi.yaml       API contract (source of truth)
internal/api/          management API handlers (+ generated apigen)
internal/auth|authz/   authentication chain, OIDC, GitLab id_tokens, RBAC
internal/formats/      raw, pypi, npm, docker, apt, yum, helm
internal/scan/         scanning pipeline (queue, drivers, policy, GitLab feedback)
internal/cleanup|routing/  cleanup policies, routing rules
internal/signing|secrets/  repository signing keys, secrets at rest
internal/proxy/        pull-through cache
internal/repo/         repository/asset service
internal/storage/      blob store drivers (file, s3)
internal/store/        Postgres persistence (+ migrations in internal/db)
pkg/client/            generated Go API client
web/                   React UI (embedded into the binary)
deploy/helm/entrepot/  Helm chart
deploy/compose/        local dev stack (Keycloak, MinIO, Postgres)
```

## Releases

Releases are cut with release-please from Conventional Commit PR titles (`feat: …`, `fix: …`).
See [CHANGELOG.md](CHANGELOG.md) for what changed and [RELEASING.md](RELEASING.md) for how
versions, images and the Helm chart are published.

## License

Apache License 2.0. See [LICENSE](LICENSE).
