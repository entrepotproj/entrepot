# Authentication & authorization

Every client — browser, `pip`, `npm`, `docker`, Terraform, GitLab CI — goes
through one authenticator. A request may carry:

| Credential | How it is sent | Identity |
|---|---|---|
| UI session | `entrepot_session` cookie after OIDC login | the OIDC user |
| Entrepot API token (`ent_…`) | `Authorization: Bearer`, or as the **password** in Basic auth (any username) | the token's user or service account, limited to the token's scopes |
| OIDC access token | `Authorization: Bearer` (or Basic password) | the OIDC user (e.g. Keycloak) |
| GitLab CI/CD `id_token` | `Authorization: Bearer` (or Basic password) | the CI job, mapped to **GitLab trust policies** |
| Registry token | issued by `/v2/token` for Docker clients | whatever authenticated at `/v2/token` |
| Bootstrap token | `Authorization: Bearer` | break-glass superuser |

Requests without credentials are anonymous. Credentials that are present but
invalid are rejected with `401`, never downgraded to anonymous.

## Authorization model

* **Actions**: `read`, `write` (upload/overwrite), `delete`, `admin`.
* **Roles** are sets of actions. Built-in: `viewer` (read), `developer`
  (read, write), `maintainer` (read, write, delete), `admin` (all). Custom
  roles can be created.
* **Role bindings** grant a role to a **subject** on repositories matching a
  **pattern**:
  * `user` — an OIDC username, or a service account (`sa:<name>`)
  * `group` — an OIDC group (from the configured groups claim)
  * `gitlab_policy` — every CI job matching a GitLab trust policy
  * `authenticated` — anyone who is logged in
* **Patterns** are globs over repository names: `*` (all), `npm-*`,
  `pypi-internal|pypi-proxy`.
* A binding of a role containing `admin` on pattern `*` makes the subject a
  **system administrator** (blob stores, repositories, security settings).
  Users in `auth.adminGroups` / `auth.adminUsers` are administrators too.
* Repositories with `anonymousRead: true` can be read by anyone (when
  `auth.anonymousAccess` is enabled).
* API tokens may be restricted with **scopes** (e.g. a `read`-only token for a
  build machine). A scoped credential cannot create a broader token.

**Group repositories** are authorised as a whole: read access to a group
grants read access to content served through it from any member, as in
Nexus. Don't put private hosted repositories into a group that has
`anonymousRead` enabled, or into a group that is readable by a wider audience
than the members are.

Repositories the caller cannot read are reported as `404` by the management
API, so repository names are not disclosed.

## Keycloak (OIDC single sign-on)

1. Create a confidential client, e.g. `entrepot`:
   * *Standard flow* on; valid redirect URI `https://entrepot.example.com/auth/callback`;
     post-logout redirect URI `https://entrepot.example.com/*`.
   * PKCE method `S256`.
2. Add a **Group Membership** mapper: claim name `groups`, *Full group path*
   off (or on: a leading `/` is stripped), added to the ID token, access
   token and userinfo.
3. Optionally add an **Audience** mapper including `entrepot` in access
   tokens. Bearer access tokens are accepted when `azp` is the client ID or
   `aud` contains one of `auth.oidc.bearerAudiences` (default: the client ID).
4. Configure Entrepot:

```yaml
server:
  baseURL: https://entrepot.example.com
auth:
  adminGroups: [entrepot-admins]
  oidc:
    enabled: true
    issuerURL: https://keycloak.example.com/realms/platform
    clientID: entrepot
    clientSecret: ...        # or ENTREPOT_AUTH_OIDC_CLIENTSECRET
    groupsClaim: groups
    usernameClaim: preferred_username
```

5. Grant access, e.g. let the `developers` group publish to every `*-internal`
   repository:

```bash
curl -H "Authorization: Bearer $ADMIN" -X POST $ENTREPOT/api/v1/role-bindings \
  -d '{"role":"developer","subjectType":"group","subject":"developers","repositoryPattern":"*-internal"}'
```

Any OIDC provider that supports discovery works (Dex, Okta, Entra ID, Auth0,
GitLab itself).

Discovery is lazy and retried, so Entrepot starts even if the IdP is down.
Keycloak access tokens can also be used directly as bearer tokens, for
example from scripts that use the client-credentials flow.

## GitLab CI/CD id_tokens

GitLab can issue each job a short-lived, signed OIDC token
([`id_tokens`](https://docs.gitlab.com/ee/ci/yaml/#id_tokens)). Entrepot
verifies it against the GitLab instance's JWKS, so pipelines can publish
packages **without stored secrets**.

1. Trust the GitLab instance:

```yaml
auth:
  gitlab:
    - name: gitlab
      issuerURL: https://gitlab.example.com
      audience: https://entrepot.example.com   # defaults to server.baseURL
```

2. Create a **trust policy** that describes which jobs are trusted. Conditions
   are claim → glob, and all of them must match. Useful claims are
   `project_path`, `namespace_path`, `ref`, `ref_type`, `ref_protected`,
   `environment` and `pipeline_source`. In patterns, `*` stops at `/` and
   `**` matches across it.

```bash
curl -H "Authorization: Bearer $ADMIN" -X POST $ENTREPOT/api/v1/gitlab-trust-policies -d '{
  "name": "platform-releases",
  "gitlab": "gitlab",
  "conditions": {"project_path": "platform/**", "ref_protected": "true"}
}'
```

3. Bind a role to the policy:

```bash
curl -H "Authorization: Bearer $ADMIN" -X POST $ENTREPOT/api/v1/role-bindings \
  -d '{"role":"developer","subjectType":"gitlab_policy","subject":"platform-releases","repositoryPattern":"npm-internal"}'
```

4. Use the token in the pipeline:

```yaml
publish:
  image: node:22
  id_tokens:
    ENTREPOT_TOKEN:
      aud: https://entrepot.example.com
  script:
    - npm config set registry https://entrepot.example.com/repository/npm-internal/
    - npm config set //entrepot.example.com/repository/npm-internal/:_authToken "$ENTREPOT_TOKEN"
    - npm publish

push-image:
  id_tokens:
    ENTREPOT_TOKEN:
      aud: https://entrepot.example.com
  script:
    - echo "$ENTREPOT_TOKEN" | docker login entrepot.example.com -u gitlab-ci --password-stdin
    - docker push entrepot.example.com/docker-internal/my-app:$CI_COMMIT_SHORT_SHA

pypi:
  id_tokens:
    ENTREPOT_TOKEN:
      aud: https://entrepot.example.com
  script:
    - twine upload --repository-url https://entrepot.example.com/repository/pypi-internal/ -u gitlab-ci -p "$ENTREPOT_TOKEN" dist/*
```

Jobs whose claims match no policy authenticate but get no permissions beyond
anonymous access. Tokens with the wrong audience, an unknown issuer or an
expired signature get `401`. Audit records show the job as
`gitlab:<project_path>@<ref>#<job_id>`.

## Service accounts and API tokens

Service accounts are non-human users for systems that cannot use OIDC or
GitLab id_tokens (Jenkins, Terraform, laptops):

```bash
curl -H "Authorization: Bearer $ADMIN" -X POST $ENTREPOT/api/v1/service-accounts -d '{"name":"jenkins"}'
curl -H "Authorization: Bearer $ADMIN" -X POST $ENTREPOT/api/v1/role-bindings \
  -d '{"role":"developer","subjectType":"user","subject":"sa:jenkins","repositoryPattern":"*"}'
curl -H "Authorization: Bearer $ADMIN" -X POST $ENTREPOT/api/v1/service-accounts/jenkins/tokens \
  -d '{"name":"ci","scopes":["read","write"],"expiresInDays":90}'
```

Users create personal tokens in the UI (*API tokens*) or with
`POST /api/v1/tokens`. Tokens are stored as SHA-256 hashes. The secret is
shown once.

## Bootstrap token

`auth.bootstrapToken` (or `ENTREPOT_AUTH_BOOTSTRAPTOKEN`, or a file named by
`ENTREPOT_AUTH_BOOTSTRAPTOKEN_FILE`) is a superuser bearer token for first-time
setup and emergencies. Remove it once OIDC admin groups or bindings are in
place.

## Browser security

Session cookies are `HttpOnly` and `SameSite=Lax`, and `Secure` when the base
URL is https. They are encrypted with AES-GCM using a key derived from
`auth.sessionSecret`. State-changing API requests that authenticate with the
cookie must send `X-Entrepot-CSRF: 1`, which a cross-site page cannot do
without a CORS preflight, and Entrepot never allows those.
