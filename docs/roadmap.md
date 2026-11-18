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

## Phase 2 — more formats and the scanning pipeline

* **Formats**
  * Apt: proxy, plus hosted with generated, GPG-signed `Release`/`InRelease`.
  * Yum/RPM: proxy, plus hosted with `repodata` generation.
  * Helm: HTTP `index.yaml` repositories, hosted and proxy. OCI charts already
    work through Docker repositories.
* **Scanning**
  * Scanner drivers configured through the API:
    * `trivy` (Trivy server mode),
    * `grype`,
    * `http-webhook`: Entrepot POSTs the asset's coordinates and a
      short-lived download URL, and the scanner calls back with SARIF or
      CycloneDX VEX,
    * `k8s-job`: runs any scanner image as a Kubernetes Job.
  * Triggers: on upload, on first proxy fetch, on demand
    (`POST /api/v1/assets/{id}/scan`), and scheduled rescans.
  * The job queue is a Postgres table read with `FOR UPDATE SKIP LOCKED`, so
    no extra infrastructure is needed.
  * Normalised findings, a per-repository policy (*warn* or *quarantine*: block
    downloads until the asset is clean or waived), waivers, and findings in the UI.
* **Dependency-confusion protection** for groups. Today npm and PyPI groups
  merge versions from all members (the first member wins per version). Add
  routing rules, such as "names in `@acme/*` or present in hosted members
  never come from proxies", and per-repository allow/deny lists.
* **Cleanup policies**: by age, last download or regex. Docker untagged
  manifest cleanup.
* **Secrets at rest**: encrypt proxy passwords and S3 keys stored in Postgres.
* GitLab feedback: commit statuses and MR comments with scan results.

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
