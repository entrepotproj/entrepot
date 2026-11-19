# Roadmap

Entrepot is being built in phases. Phase 1 is the core and has shipped.

## Phase 1 — core (done)

* Single Go binary: format endpoints, management API, embedded React UI,
  background maintenance.
* Postgres metadata. Content-addressed blob stores: `file` (PVC/EBS/EFS) and `s3`.
  Each repository picks its own store.
* Formats: **raw**, **PyPI**, **npm**, **Docker/OCI**, each hosted + proxy + group.
* Authentication: Keycloak/OIDC login and bearer tokens, **GitLab CI/CD
  id_tokens** with trust policies, API tokens, service accounts, bootstrap
  token. RBAC with roles and bindings. Audit log.
* OpenAPI 3 spec with Swagger UI (`/api/docs`) and a generated Go client (`pkg/client`).
* Helm chart (EBS / EFS / S3 examples, IRSA), Dockerfile, docker compose dev
  stack with Keycloak and MinIO, CI with a kind smoke test.

## Phase 2: more formats and the scanning pipeline (done)

* **Apt**: hosted, with generated `Packages`/`Release` and a signed
  `InRelease`/`Release.gpg`; proxy.
* **Yum/RPM**: hosted, with createrepo-compatible repodata and a signed
  `repomd.xml`; proxy.
* **Helm**: HTTP repositories (hosted with the ChartMuseum API, proxy, group).
* **Signing keys** per repository, managed by Entrepot, with rotation and
  import.
* **Scanning pipeline**: Trivy, Grype and webhook scanners; a Postgres job
  queue; warn or quarantine policies with waivers; scheduled rescans; a
  separate scan-worker image and Deployment; GitLab commit statuses and MR
  notes.
* **Cleanup policies** (age, downloads, regex, prerelease, keep-latest,
  untagged Docker manifests) with preview and a scheduled run.
* **Routing rules** for proxies, and **prefer-hosted** groups against
  dependency confusion.
* **Secrets at rest**: AES-GCM encryption of proxy passwords, S3 keys,
  scanner secrets and signing keys, with key rotation.

### Follow-ups

* Apt/Yum group repositories (these need re-signing of merged metadata).
* Signing individual RPM packages, not just repository metadata.
* Kubernetes Job scanner driver (one Job per scan).
* Filtering npm/PyPI search results by prefer-hosted.

## Phase 3 — Terraform provider

`terraform-provider-entrepot` will be built on terraform-plugin-framework and
the generated `pkg/client`.

* Resources: `entrepot_blob_store`, `entrepot_repository` (with nested
  `proxy`, `hosted`, `group` and `scan_policy` blocks), `entrepot_role`,
  `entrepot_role_binding`, `entrepot_gitlab_trust_policy`,
  `entrepot_service_account`, `entrepot_api_token` and `entrepot_scanner`.
* Data sources and import support for each.
* Acceptance tests against a server started in CI, and goreleaser publishing
  to the Terraform Registry.

The management API is designed for the provider: every object has a stable
name or ID, PUT replaces mutable fields, write-only secrets are never
returned, and the immutable fields (format, kind, blob store) map to
`RequiresReplace`.
