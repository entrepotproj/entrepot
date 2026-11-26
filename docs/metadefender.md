# MetaDefender Core

The `metadefender` scanner sends the files of each component to
[OPSWAT MetaDefender Core](https://www.opswat.com/products/metadefender/core)
(REST API, version 5) for multi-engine malware analysis. Trivy and Grype look
up known vulnerabilities from a package's name and version; MetaDefender reads
the bytes, so it finds malware, suspicious and potentially unwanted files, and
files its workflow rule refuses (encrypted archives, archive bombs, blocked
file types, …).

It runs like any other scanner: on upload, when a proxy first caches a file,
on demand and on the rescan schedule. Repositories opt in by selecting it.

## Set up

1. In MetaDefender, pick or create a **workflow rule** for packages (for
   example a copy of *File process* with archive extraction enabled and the
   archive limits raised to suit your largest packages), and an **API key**
   if your server requires authentication.
2. Create the scanner:

   ```bash
   curl -H "Authorization: Bearer $ADMIN" -X POST $E/api/v1/scanners -d '{
     "name": "metadefender", "type": "metadefender", "rescanIntervalHours": 168,
     "metadefender": {
       "url": "https://metadefender.example.com:8008",
       "apiKey": "…",
       "rule": "Packages",
       "webUrl": "https://metadefender.example.com:8008/#/public/process/dataId/{dataId}"
     }
   }'
   curl -H "Authorization: Bearer $ADMIN" -X POST $E/api/v1/scanners/metadefender/test
   ```

   The test checks `/readyz` (database and licence), the API key
   (`/version`), and that the rule is available to the key (`/file/rules`).
3. Select it in the repositories to protect, with quarantine mode. For
   malware scanning you'll usually want:

   ```json
   {"scan": {"scanners": ["metadefender"], "mode": "quarantine", "severityThreshold": "high",
             "blockUntilScanned": true, "holdSeconds": 60, "blockOnError": true}}
   ```

   It combines with Trivy or Grype: `"scanners": ["trivy", "metadefender"]`.

| Setting | Default | |
|---|---|---|
| `url` | required | MetaDefender Core REST API |
| `apiKey` | none | sent in the `apikey` header; encrypted at rest and never returned. Omitting it on update keeps the stored key only while `url` is unchanged |
| `rule` | server default | workflow rule (sent URL-encoded in the `rule` header) |
| `timeoutSeconds` | 600 | time to analyse all files of a component; on timeout the analyses are cancelled and the job retried |
| `concurrency` | 4 | files of one component analysed at once (max 32) |
| `hashLookup` | true | reuse earlier analyses (see below) |
| `maxResultAgeHours` | 24 | oldest analysis reused |
| `webUrl` | none | link from findings to the MetaDefender console; `{dataId}` is replaced |
| `caCertificate` | none | PEM certificates to trust for `url` (internal CAs) |

## What is sent

Every file of the component, streamed from the blob store as the raw body of
`POST /file` (with `Content-Length` and the `filename` header), except files
derived from the package: PyPI `.metadata` and Helm `.prov` sidecars. Nothing
is written to the scan work directory. Helm charts, which Trivy and Grype
can't scan, are covered. Docker images are sent layer by layer (below).

Each analysis is polled (`GET /file/{data_id}`, every 250 ms backing off to
2 s) until it finishes. A full queue (`503`) is retried with backoff until the
job's deadline. MetaDefender must report the sha256 of the content Entrepot
sent, or the scan fails.

**Hash lookup.** Before uploading, Entrepot asks `GET /hash/{sha256}`
(`selfonly`, `timerange` set from `maxResultAgeHours`) and reuses the analysis
only if it finished, was processed by the same rule (`process_info.profile`),
has no `outdated_data` (engine definitions haven't moved on since) and is
younger than `maxResultAgeHours`. Without a `rule`, results are only reused
once Entrepot has learnt the default rule's name from one of its own uploads.
Concurrent scans of the same content in one Entrepot process share a single
analysis.

## Docker images

A Docker tag is sent as its layer blobs: the unique layers of the platform
images, chosen as for Trivy image scans (every platform in hosted
repositories, up to 8; in proxies the platforms already cached, or
linux/amd64). Config blobs are not sent.

* A layer's sha256 is its digest, so a base layer MetaDefender has analysed
  before (for another image or tag) is matched by hash: it is not uploaded
  again, and a proxy doesn't even fetch it from the upstream.
* Findings name the layer and the platforms that use it:
  `layer sha256:3f1a2b4c5d6e (linux/amd64, linux/arm64)`, and for a blocked
  layer the file inside it.
* An infected layer quarantines the tag: its manifest is refused by tag and
  by digest (index and platform manifests). Layer blobs themselves are
  served, so a client that already knows a layer's digest can still fetch
  it.
* In a proxy, pulling a platform manifest that the last scan left out makes
  the image pending again: it is scanned with that platform and the pull is
  held for the verdict. Docker clients don't retry a `503` on a manifest, so
  give Docker repositories a generous `holdSeconds` (e.g. 300) and enough
  `timeoutSeconds` for large layers.
* Layers compressed with zstd may be reported as unsupported or blocked by
  your rule, depending on your MetaDefender version.

## Verdicts

The decision follows MetaDefender's own `process_info.result`; the result
code adds detail.

| MetaDefender | Entrepot |
|---|---|
| Blocked: Infected, Malicious/Known Bad, Threat Intelligence, OPSWAT AI malicious | `MALWARE:<threat>`, critical |
| Blocked: Suspicious, sandbox suspicious/likely malicious | `SUSPICIOUS:<threat>`, critical |
| Blocked: Potentially Unwanted | `PUA:<threat>`, critical |
| Blocked: anything else (encrypted archive, archive limits, file type, sensitive data, …) | `BLOCKED:<reason>`, critical |
| Allowed, but Infected or malicious | `MALWARE:<threat>`, critical |
| Allowed, but Suspicious or Potentially Unwanted | `SUSPICIOUS:` / `PUA:`, high |
| Allowed, anything else | clean |
| Failed, Cancelled, timeouts, in progress at the deadline, unexpected answers | scan error (retried; blocked with `blockOnError`) |

* `<threat>` is the name most engines reported, so it stays the same across
  rescans and an exact waiver keeps matching.
* For a blocked archive, `GET /file/{data_id}/blocked-leaves` names the
  files inside it: the finding's package reads `charts/app-1.0.tgz › bin/x`.
* The finding's installed version is the start of the file's sha256, and its
  title reads like `Infected: 7/9 engines`.
* Downloads are refused with
  `MALWARE:… detected by metadefender in <file> (<component>) — downloads are blocked; only a waiver for this exact finding releases it`.
* Waivers for `*` never cover these findings; a waiver for the exact ID does.

## Throughput and timeouts

* MetaDefender jobs mostly wait on the network. With holds, run more workers
  than the default 2 (`scan.workers: 8` or more), and keep `timeoutSeconds`
  below the clients' patience (see the client timeout table in
  [scanning](scanning.md)).
* Large files can hit the rule's archive size or depth limits; the rule's
  Blocked/Allowed decision applies (`BLOCKED:Exceeded Archive Size`).
* `/scans` lists each file analysed, its data id, result, and whether an
  earlier analysis was reused.

## Checking against your server

`internal/scan/drivers/mdfake/capture.sh` records your server's answers for
a clean file, the EICAR test file (assembled at runtime) and a zip containing
it, so they can be compared with the fixtures the tests use:

```bash
MD_URL=https://metadefender.example.com:8008 MD_APIKEY=… MD_RULE=Packages \
  internal/scan/drivers/mdfake/capture.sh ./md-capture
```
