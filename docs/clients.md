# Client setup

Replace `entrepot.example.com` with your server and `$TOKEN` with any token
Entrepot accepts:

* an API token (`ent_…`) from *API tokens* in the UI,
* an OIDC access token,
* a GitLab CI `id_token`.

Wherever a client wants a username and password, any username works; only the
password (the token) matters. The UI's **Set up client** panel on each
repository shows these snippets pre-filled.

Repository URLs:

* `https://entrepot.example.com/repository/<name>/` for raw, PyPI and npm,
* `entrepot.example.com/<name>/<image>` for Docker.

## Raw files

```bash
# upload (hosted)
curl -H "Authorization: Bearer $TOKEN" -T app.tar.gz \
  https://entrepot.example.com/repository/files/releases/1.4.0/app.tar.gz
# download (also works for proxy and group repositories)
curl -fLO -u token:$TOKEN https://entrepot.example.com/repository/files/releases/1.4.0/app.tar.gz
# directory listing
curl -u token:$TOKEN https://entrepot.example.com/repository/files/releases/
# delete a file, or a directory (trailing slash)
curl -X DELETE -H "Authorization: Bearer $TOKEN" https://entrepot.example.com/repository/files/releases/1.4.0/
```

You can also upload through the API (`POST /api/v1/repositories/{name}/upload`)
or the UI.

## PyPI (pip, uv, poetry, twine)

```ini
# ~/.config/pip/pip.conf  (or /etc/pip.conf)
[global]
index-url = https://__token__:${TOKEN}@entrepot.example.com/repository/pypi-group/simple/
```

```bash
pip install --index-url https://entrepot.example.com/repository/pypi-proxy/simple/ requests
uv pip install --index-url https://__token__:$TOKEN@entrepot.example.com/repository/pypi-group/simple/ mypkg
twine upload --repository-url https://entrepot.example.com/repository/pypi-internal/ -u __token__ -p "$TOKEN" dist/*
```

```ini
# ~/.pypirc
[distutils]
index-servers = entrepot
[entrepot]
repository = https://entrepot.example.com/repository/pypi-internal/
username = __token__
password = <TOKEN>
```

Notes:

* The simple index speaks PEP 503 (HTML) and PEP 691 (JSON), and serves PEP 658
  metadata files, so pip resolves without downloading whole wheels.
* File links are relative. Credentials embedded in the index URL keep working
  for downloads.
* Proxies verify each file's sha256 against the upstream index before caching it.

## npm (npm, yarn, pnpm)

```ini
# .npmrc
registry=https://entrepot.example.com/repository/npm-group/
//entrepot.example.com/repository/npm-group/:_authToken=${TOKEN}
//entrepot.example.com/repository/npm-internal/:_authToken=${TOKEN}
```

```bash
npm publish --registry https://entrepot.example.com/repository/npm-internal/
npm dist-tag add mypkg@1.2.0 stable --registry https://entrepot.example.com/repository/npm-internal/
npm whoami --registry https://entrepot.example.com/repository/npm-internal/
# interactive login: use your Entrepot token as the password
npm login --registry https://entrepot.example.com/repository/npm-internal/ --auth-type=legacy
```

Notes:

* Scoped packages work.
* `npm deprecate`, `npm unpublish` (needs `delete`), `npm search` and
  `npm audit` all work; audit is forwarded to the proxy's upstream.
* Entrepot computes `shasum` and `integrity` itself on publish.
* Proxies verify tarball integrity before caching.

## Docker / OCI

The first path segment is the Entrepot repository:

```bash
echo "$TOKEN" | docker login entrepot.example.com -u token --password-stdin

# pull through a Docker Hub proxy repository called docker-hub
docker pull entrepot.example.com/docker-hub/library/alpine:3.20
docker pull entrepot.example.com/docker-hub/alpine:3.20        # library/ is implied for Docker Hub

# push to a hosted repository called docker-internal
docker tag my-app:1.0 entrepot.example.com/docker-internal/team/my-app:1.0
docker push entrepot.example.com/docker-internal/team/my-app:1.0

# crane / skopeo / helm OCI work the same way
crane ls entrepot.example.com/docker-internal/team/my-app
helm push mychart-0.1.0.tgz oci://entrepot.example.com/docker-internal/charts
```

Notes:

* For plain-HTTP test setups, add the host to Docker's `insecure-registries`.
* Hosted Docker repositories allow moving tags by default. Set
  `hosted.allowRedeploy: false` for immutable tags.
* Docker Hub pull-rate limits apply to the proxy's upstream account. Set
  `proxy.username`/`password` on the repository to use an authenticated quota.
  Tags are revalidated with cheap HEAD requests, which don't count as pulls.

### containerd / Kubernetes mirror

To make a cluster pull Docker Hub images through Entrepot, configure a
registry mirror. For example, for containerd in
`/etc/containerd/certs.d/docker.io/hosts.toml`:

```toml
server = "https://registry-1.docker.io"
[host."https://entrepot.example.com/v2/docker-hub"]
  capabilities = ["pull", "resolve"]
  override_path = true
```

## GitLab CI

See [authentication.md](authentication.md#gitlab-cicd-id_tokens). In short,
request an `id_token` whose `aud` is the Entrepot base URL, and use
`$ENTREPOT_TOKEN` anywhere a token is expected above.

## Terraform and scripts

Use the REST API (`/api/docs`) with a service-account token. For Go, use the
generated client in `pkg/client`. A Terraform provider is planned (see the
[roadmap](roadmap.md)).
