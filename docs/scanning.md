# Vulnerability scanning

Entrepot can scan components when they are uploaded, when a proxy first
caches them, on demand, and on a schedule. Each repository decides what to do
with the results: just record them (**warn**) or block downloads
(**quarantine**). Builds published from GitLab CI get the results back as a
commit status and an MR note.

```
 upload / proxy fetch ──► scan_jobs (Postgres queue) ──► worker ──► trivy | grype | webhook | metadefender
                                                             │
                     download ◄── quarantine gate ◄── verdict ◄── findings − waivers
                                                             └──► GitLab commit status + MR note
```

## Scanners

Scanners are configured in the UI (*Administration → Scanners*) or with the
API. A scanner is one of four types:

| Type | How it runs | Best for |
|---|---|---|
| `trivy` | runs the `trivy` CLI. With `serverUrl` set it uses client/server mode, so a central Trivy server keeps the vulnerability DB | most deployments |
| `grype` | runs the `grype` CLI | a second opinion, or when you already use Anchore |
| `webhook` | POSTs a signed job to your service, which calls back with results | in-house or commercial scanners (Snyk, Xray, Dependency-Track, …) |
| `metadefender` | uploads each file of a component to OPSWAT MetaDefender Core for multi-engine malware analysis | malware, archive and file-policy checks; see [MetaDefender Core](metadefender.md) |

```bash
curl -H "Authorization: Bearer $ADMIN" -X POST $E/api/v1/scanners -d '{
  "name": "trivy", "type": "trivy", "rescanIntervalHours": 24,
  "trivy": {"serverUrl": "http://entrepot-trivy:4954"}
}'
curl -H "Authorization: Bearer $ADMIN" -X POST $E/api/v1/scanners/trivy/test
```

Secret settings, the Trivy `serverToken`, the webhook `secret` and the
MetaDefender `apiKey`, are
encrypted at rest and never returned by the API. You can't delete a scanner
while a repository still uses it (`409`).

### Where scans run

* **In-process.** The default is `scan.workers: 2`. The default server image is
  distroless and has no scanner CLIs, so in-process workers only suit `webhook`
  scanners, or `trivy` with the CLI added to the image.
* **Separate workers.** `entrepot scan-worker` runs only the pipeline. The
  `scanner` image target bundles checksum-verified `trivy` and `grype`
  binaries. The Helm chart deploys it with `scanning.worker.enabled: true`
  and, optionally, a shared Trivy server with `scanning.trivyServer.enabled:
  true`. In-process workers are then switched off.

Jobs live in a Postgres table. Workers claim them with
`FOR UPDATE SKIP LOCKED` and hold a lease, which they extend with a heartbeat.
Expired leases are reclaimed, and failures are retried with exponential
backoff (up to three attempts by default). Any number of workers can run on
any number of replicas.

## What gets scanned

| Format | Target |
|---|---|
| npm, PyPI | a one-component CycloneDX SBOM with the package's purl (`pkg:npm/lodash@4.17.20`) |
| Apt, Yum | a deb or rpm purl plus an operating-system component from the repository's `scan.distro`, e.g. `debian-12`, `ubuntu-24.04`, `rocky-9` |
| Docker | the image is exported from the blob store as an OCI layout, one per platform (up to 8), and the findings are merged. A proxy scans the platforms it has cached, or linux/amd64 |
| Helm, raw | reported as `unsupported` by Trivy, Grype and webhooks |

In raw repositories with scanning enabled, every file is a component named
after its path (with no version), so it is scanned and gated like a package:
on upload, when a proxy first caches it, and when it is replaced. Files
stored before scanning was switched on get their components in the
background when it is switched on (and at startup), or at the latest when
they are downloaded; like other components stored before scanning, they are
scanned on demand, by a rescan, or at download with `blockUntilScanned`.

Scanners that read content (`metadefender`) are sent the component's files
instead: every format's package files, Helm charts included, except files
derived from the package (PyPI `.metadata`, Helm `.prov`). Docker images are
sent layer by layer, for the same platforms as image scans; see
[MetaDefender Core](metadefender.md#docker-images).

## Repository policy

```json
"scan": {
  "scanners": ["trivy"],
  "mode": "quarantine",
  "severityThreshold": "high",
  "onUpload": true,
  "onProxyFetch": true,
  "blockUntilScanned": false,
  "holdSeconds": 0,
  "blockOnError": false,
  "distro": "debian-12"
}
```

* **Component state** is one of:
  * `unscanned`;
  * `pending` (queued, never scanned yet);
  * `clean` (no unwaived findings);
  * `vulnerable` (unwaived findings);
  * `error`;
  * `unsupported`.

  The state comes from the latest result of each scanner, minus active waivers.
* **Warn mode** records results and never blocks.
* **Quarantine mode** blocks downloads of components that have an unwaived
  finding at or above `severityThreshold`. Blocked downloads get `403` with a
  reason, for example `CVE-2021-23337 (high) in lodash@4.17.20 — waive or fix
  to download`, and the header `X-Entrepot-Quarantined: true`.
  * Metadata (packuments, indexes) is not blocked, so clients see a clear
    error on the file itself.
  * Docker tag manifests and digest manifests are blocked; layers never are.
* **Block until scanned** (quarantine mode only) also blocks components that
  have not been scanned yet. The download attempt queues the scan.
* **Hold until verdict** (`holdSeconds`, with `blockUntilScanned`): instead
  of refusing a download of content that is still being scanned, keep the
  request open for up to `holdSeconds` (1–600) and answer as soon as the
  verdict is in: the file, or `403` if it is quarantined. The component's
  queued scans move to the front of the queue. If the hold runs out the
  client gets `503` with `Retry-After: 10` and `X-Entrepot-Scan-Pending:
  true`. `0` (the default) keeps the immediate `403`.
  * Sidecar files (PyPI `.metadata`, Helm `.prov`) are never held: pip reads
    them while resolving, often for many versions. A quarantine still
    blocks them.
  * Held downloads are woken through Postgres notifications, so a verdict
    from a separate scan-worker deployment or another replica releases them
    at once; otherwise they poll (every second at most).
  * At most `scan.maxHolds` downloads are held per process; more get `503`
    at once. Draining pods answer held downloads with `503`.
  * Prometheus: `entrepot_scan_hold_duration_seconds{outcome}` (served,
    blocked, timeout, cancelled, refused) and `entrepot_scan_holds_active`.
  * Choose the hold per format: clients and load balancers time out on a
    response that sends nothing.

    | Client or proxy | Gives up after | On `503` | Suggested `holdSeconds` |
    |---|---|---|---|
    | pip | 15s without data (`--timeout`) | retries 5 times | 10 |
    | apt | about 30s | per `Acquire::Retries` | 20 |
    | dnf / yum | 30s (low-speed timeout) | retries | 20 |
    | npm | 300s (`fetch-timeout`) | retries twice | 60 |
    | Docker, containerd | rarely | doesn't retry manifests | 300 |
    | AWS ALB | 60s idle timeout by default | — | stay below it |
    | nginx ingress (this chart) | 900s (`proxy-read-timeout`) | — | stay below it |

    `server.readTimeout` must be `0` (the default) or longer than the hold.
    Run enough scan workers (`scan.workers`) that scans of new content start
    promptly.
* **Block on scan errors** (`blockOnError`, quarantine mode only) fails
  closed: a component whose latest scan by a configured scanner failed is
  blocked with `… could not be scanned; downloads are blocked until a scan
  succeeds`. Failed scans are queued again every `scan.errorRetryInterval`
  (default 15 minutes), and a download attempt retries them once the failure
  is more than a minute old (with `holdSeconds`, the download waits for that
  retry). Use it with `blockUntilScanned`.
* **Strict verdicts.** Repositories with `blockOnError`, or with a
  `metadefender` scanner selected, decide a component's state only once every
  configured scanner has scanned its current content (so a fast Trivy result
  never releases a file MetaDefender hasn't analysed yet).
  * Until then the component is `pending`. Other repositories keep the
    original rule: the first completed scan decides, and later results update
    the state.
  * A new or changed file in a component (another wheel of a version, a
    re-upload, a Docker tag that moved) makes it `pending` again and queues a
    scan. A scan that was already running when the file arrived is repeated.
  * Sidecar files (PyPI `.metadata`, Helm `.prov`) are derived from the
    package and don't count as new content.
  * A Docker proxy scans the platforms of an index it has cached (or
    linux/amd64). Pulling a platform manifest that the last scan left out
    counts as new content: the image is scanned again with that platform, and
    the pull waits for it like any pending download.
* Switching a repository from warn to quarantine takes effect immediately,
  without rescanning.

## Waivers

A waiver accepts a vulnerability.

* `vulnId` is an exact ID, or `*`. `*` never covers threats reported by file
  scanners (IDs starting `MALWARE:`, `SUSPICIOUS:`, `PUA:` or `BLOCKED:`);
  those need a waiver for the exact ID.
* `repositoryPattern` and `componentPattern` are globs. The component
  pattern is matched against `name`, `name@version` or `name:version`.
* `expiresAt` is optional. When a waiver expires, the components it covered
  are re-evaluated.
* A waiver of `*` for everything at once is rejected.

Creating, changing or deleting a waiver re-evaluates the affected components
straight away.

```bash
curl -H "Authorization: Bearer $ADMIN" -X POST $E/api/v1/waivers -d '{
  "vulnId": "CVE-2021-23337", "repositoryPattern": "npm-*", "componentPattern": "lodash@4.17.*",
  "reason": "template() not used with untrusted input", "expiresAt": "2027-01-31T00:00:00Z"
}'
```

## On-demand scans and results

```bash
curl -H "Authorization: Bearer $TOKEN" -X POST $E/api/v1/components/$ID/scan        # needs write
curl -H "Authorization: Bearer $TOKEN" $E/api/v1/components/$ID/scans                # findings, jobs, verdict
curl -H "Authorization: Bearer $ADMIN" "$E/api/v1/scan-jobs?status=failed"           # queue
```

Scanners with `rescanIntervalHours` periodically rescan components that
repositories still use, so new CVEs are picked up for old artifacts.

## Finding vulnerable and quarantined components

The dashboard's **Vulnerable** and **Quarantined** tiles link to the search
page filtered by that state, where a **Findings** column lists each
component's findings with links to the advisories. The search page also has a
security-state filter.

The same filters are on the search API:

```bash
curl -H "Authorization: Bearer $TOKEN" "$E/api/v1/search?scanState=vulnerable&withFindings=true"
curl -H "Authorization: Bearer $TOKEN" "$E/api/v1/search?quarantined=true&repository=npm-libs"
```

* `scanState` returns only components in that [state](#repository-policy).
  An unknown state is rejected with `400`.
* `quarantined` returns only quarantined (`true`) or only other (`false`)
  components.
* `withFindings=true` adds two fields to each component:
  * `findingCounts`: the number of findings by severity;
  * `findings`: the five most severe findings. `findingCounts` counts all of
    them.

  Both leave out findings covered by an active waiver, and count a
  vulnerability reported by several scanners once, as the component's state
  does.

They combine with the other search parameters (`q`, `format`, `repository`,
`version`, `limit`, `offset`), and search only returns components in
repositories the caller can read.

## Webhook protocol

Entrepot sends:

```http
POST <webhook url>
X-Entrepot-Signature: sha256=<hex HMAC-SHA256(secret, body)>
X-Entrepot-Event: scan

{"type":"scan","jobId":"…","scanner":"xray","repository":"npm-proxy","target":"package",
 "component":{"id":"…","name":"lodash","version":"4.17.20","format":"npm","purl":"pkg:npm/lodash@4.17.20"},
 "artifactUrl":"https://entrepot/api/v1/scan-jobs/<id>/artifact?token=esj_…",
 "callbackUrl":"https://entrepot/api/v1/scan-jobs/<id>/result",
 "token":"esj_…","expiresAt":"…"}
```

How the scanner responds:

1. Reply to the POST with any `2xx`.
2. Optionally download `artifactUrl`. Docker images come as an OCI layout tar.
3. POST the results to `callbackUrl`, sending the token in
   `Authorization: Bearer <token>` or `?token=`. The body is one of:
   * `{"format":"entrepot","findings":[{"vulnId","severity","package","installedVersion","fixedVersion","title","url"}]}`;
   * `{"format":"sarif","document":{…SARIF 2.1…}}`;
   * `{"format":"cyclonedx","document":{…with vulnerabilities[]…}}`;
   * `{"error":"…"}` (the job is retried);
   * `{"unsupported":true}`.

The token is single-use and expires after `timeoutSeconds` (default 900s);
the job is then retried. The scanner test sends a signed `{"type":"ping"}`.
`server.baseURL` must be set for webhook scanners.

## GitLab feedback

Entrepot posts results back to GitLab when an artifact was published by a
GitLab CI job (authenticated with its `id_token`) and that GitLab instance
has an API token configured:

```yaml
auth:
  gitlab:
    - name: gitlab
      issuerURL: https://gitlab.example.com
      api:
        tokenEnv: ENTREPOT_GITLAB_TOKEN   # a token with the "api" scope (or token / tokenFile)
```

* **Commit status** `entrepot/scan/<repository>` on the pipeline's commit:
  * `running` while scans are outstanding;
  * then `failed` when the component is quarantined or has unwaived findings
    at or above the threshold;
  * otherwise `success`.

  It links to the component page in the UI.
* **MR note** on each open merge request for that commit. There is one note
  per repository and component, updated in place on rescans, with a findings
  table.

Feedback is best effort. Errors are logged and never fail a scan.

## Limitations

* The vulnerability databases must be reachable from the scanners: through
  the Trivy server, or `mirror.gcr.io` / ghcr for Trivy and `grype.anchore.io`
  for Grype. For air-gapped setups, mirror the DBs and pass `extraArgs`
  (e.g. `--db-repository`).
* Group repositories apply each member's policy, not the group's.
* Download-gate decisions are cached per process for up to 30 seconds after a
  waiver change.
