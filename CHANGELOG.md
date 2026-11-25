# Changelog

## 0.1.0

First release. It publishes the images `ghcr.io/entrepotproj/entrepot` and
`ghcr.io/entrepotproj/entrepot-scanner` and the Helm chart
`oci://ghcr.io/entrepotproj/charts/entrepot`.

* Formats: raw, PyPI, npm, Docker/OCI and Helm, each with hosted, proxy and group repositories;
  Apt and Yum with hosted and proxy repositories and per-repository GPG signing.
* Proxies revalidate with conditional requests, collapse concurrent misses, cache 404s and keep
  serving cached content when the upstream is down.
* Blob stores on a file system (PVC, EBS, EFS) or S3, content-addressed and deduplicated.
* Authentication: OIDC single sign-on (for example Keycloak) with group-based roles, API tokens,
  service accounts, and GitLab CI `id_token`s matched by trust policies.
* Role-based access control, with role bindings scoped to repository patterns.
* Vulnerability scanning with Trivy, Grype or a signed webhook, on upload, on proxy fetch, on
  demand or on a schedule. Repositories warn or quarantine, with waivers, and results are posted
  back to GitLab.
* Cleanup policies, routing rules, and groups that prefer hosted packages to block dependency
  confusion. Secrets are encrypted at rest.
* A spec-first management API (OpenAPI 3) with Swagger UI at `/api/docs`, and a generated Go
  client in `pkg/client`.
* Web UI: browse, search and upload; manage repositories, tokens and access control; a dashboard
  with usage metrics, activity and audit views, and vulnerable and quarantined components.
* Runs as one static binary plus Postgres, with a Helm chart, Prometheus metrics and health
  probes.
