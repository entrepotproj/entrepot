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

### A repository's own hostname

A Docker repository can also be served on its own hostname, set with
`docker.host` (UI: the repository's **Hostname**). On that host `/v2/` is
the repository, so images have no repository prefix:

```bash
docker pull hub.entrepot.example.com/library/alpine:3.20
docker push registry.acme.example.com/team/my-app:1.0
```

* Point DNS for the name at Entrepot and give the ingress or load balancer a
  certificate for it. A wildcard record and certificate
  (`*.entrepot.example.com`) cover every repository hostname; see the Helm
  chart's `examples/docker-hosts.yaml`.
* The path form (`entrepot.example.com/<repository>/<image>`) keeps working,
  so clients can move over gradually.
* Log in to the hostname itself (`docker login hub.entrepot.example.com`).
  The token endpoint is on the same host.
* A hostname belongs to one repository, and can't be the server's own host.

### Registry mirrors

With a hostname on a Docker Hub proxy, Docker Engine can use Entrepot as its
mirror for every `docker pull` of a Docker Hub image, in
`/etc/docker/daemon.json`:

```json
{ "registry-mirrors": ["https://hub.entrepot.example.com"] }
```

The daemon sends the mirror the user's Docker Hub credentials, if any, so
the proxy repository needs `anonymousRead`. On a repository hostname that
allows anonymous reads, Entrepot answers credentials it doesn't recognise
with an anonymous token, so the mirror is used rather than skipped. If the
mirror can't serve an image, the daemon falls back to Docker Hub.

For containerd (Kubernetes nodes), in
`/etc/containerd/certs.d/docker.io/hosts.toml`:

```toml
server = "https://registry-1.docker.io"
[host."https://hub.entrepot.example.com"]
  capabilities = ["pull", "resolve"]
```

Without a hostname, containerd can still use the path form:

```toml
server = "https://registry-1.docker.io"
[host."https://entrepot.example.com/v2/docker-hub"]
  capabilities = ["pull", "resolve"]
  override_path = true
```

## Apt (Debian / Ubuntu)

Hosted Apt repositories sign their metadata with a key Entrepot generates per
repository:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://entrepot.example.com/repository/apt-internal/public.gpg \
  | sudo tee /etc/apt/keyrings/entrepot-apt-internal.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/entrepot-apt-internal.gpg] https://entrepot.example.com/repository/apt-internal stable main" \
  | sudo tee /etc/apt/sources.list.d/entrepot.list
sudo apt-get update && sudo apt-get install mypkg

# private repositories: /etc/apt/auth.conf.d/entrepot.conf
#   machine entrepot.example.com/repository/apt-internal/ login token password <TOKEN>

# upload (hosted)
curl -fu token:$TOKEN -T mypkg_1.0_amd64.deb \
  "https://entrepot.example.com/repository/apt-internal/mypkg_1.0_amd64.deb?distribution=stable&component=main"
```

* Proxies (e.g. of `http://archive.ubuntu.com/ubuntu`) serve upstream metadata
  byte for byte, so keep using the upstream keyring in `signed-by`.
* Rotate or import the signing key with `/api/v1/repositories/{name}/signing-key`.
  After a rotation apt clients must fetch the new `public.gpg`.

## Yum / dnf (RHEL, Rocky, Fedora, Amazon Linux)

```bash
sudo curl -fsSL -o /etc/yum.repos.d/entrepot.repo \
  https://entrepot.example.com/repository/yum-internal/entrepot.repo
sudo dnf install mypkg

# upload (hosted); repodata is generated at hosted.yum.repodataDepth (0 = root)
curl -fu token:$TOKEN -T mypkg-1.0-1.el9.x86_64.rpm \
  https://entrepot.example.com/repository/yum-internal/mypkg-1.0-1.el9.x86_64.rpm
```

The generated `.repo` file enables `repo_gpgcheck=1` with the repository's
key. Entrepot signs `repomd.xml` but not the packages themselves, so the file
sets `gpgcheck=0`. For private repositories add `username=`/`password=` to the
`.repo` file.

## Helm

```bash
helm repo add internal https://entrepot.example.com/repository/helm-internal/ --username token --password "$TOKEN"
helm repo update && helm install my-release internal/mychart

# upload: ChartMuseum API (works with the helm cm-push plugin) or PUT
curl --data-binary @mychart-0.1.0.tgz -H "Authorization: Bearer $TOKEN" \
  https://entrepot.example.com/repository/helm-internal/api/charts
helm cm-push mychart/ internal
```

Proxies rewrite chart URLs in the upstream `index.yaml` so downloads are
cached. Groups merge indexes and prefer hosted charts. OCI charts
(`helm push oci://entrepot.example.com/docker-internal/charts`) go to Docker
repositories.

## GitLab CI

See [authentication.md](authentication.md#gitlab-cicd-id_tokens). In short,
request an `id_token` whose `aud` is the Entrepot base URL, and use
`$ENTREPOT_TOKEN` anywhere a token is expected above.

## Terraform and scripts

Use the REST API (`/api/docs`) with a service-account token. For Go, use the
generated client in `pkg/client`. A Terraform provider is planned (see the
[roadmap](roadmap.md)).
