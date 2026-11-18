# Storage

Artifacts live in **blob stores**; metadata (repositories, components,
assets, users, permissions) lives in **Postgres**. Each repository is bound to
one blob store at creation time, so you can pick storage **per repository** —
e.g. a hot npm proxy on EBS, a large Docker registry on S3 and shared release
files on EFS.

Content is addressed by SHA-256 and deduplicated within a store: the same
layer pushed to ten images, or a wheel cached by two proxies, is stored once.
Reference counts are tracked in Postgres and unreferenced blobs are garbage
collected (every 15 minutes, after a one-hour grace period, or on demand with
`POST /api/v1/maintenance/gc` / `entrepot gc`).

## Store types

### `file` — PVC, EBS, EFS, NFS

A directory on a mounted volume. In Kubernetes this is a PersistentVolumeClaim;
the volume type is decided by its StorageClass:

| Backing | StorageClass example | Access mode | Replicas |
|---|---|---|---|
| EBS (gp3) | `gp3` (EBS CSI) | ReadWriteOnce | **1** (Deployment uses `Recreate`) |
| EFS | `efs-sc` (EFS CSI) | ReadWriteMany | many |
| Any RWX (NFS, CephFS, Filestore…) | — | ReadWriteMany | many |
| Plain PVC / hostPath / local | cluster default | ReadWriteOnce | 1 |

Layout: `blobs/sha256/<aa>/<digest>` and `temp/` (in-progress Docker uploads).
Writes go to a temp file and are atomically renamed, so readers never see
partial blobs.

The Helm chart refuses to render more than one replica when any `file` store
uses ReadWriteOnce.

### `s3` — AWS S3 and compatibles

```yaml
type: s3
s3:
  bucket: my-entrepot-artifacts
  region: eu-west-2
  prefix: prod                 # optional key prefix
  endpoint: ""                 # set for MinIO / Ceph RGW / R2
  forcePathStyle: false        # true for MinIO
  accessKeyId: ""              # empty = AWS default chain (IRSA, env, instance profile)
  secretAccessKey: ""
  redirectDownloads: true      # 307 large downloads to presigned S3 URLs
```

On EKS use IRSA. Annotate the chart's service account with the role ARN. The
role needs `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket`
and `s3:AbortMultipartUpload` on the bucket.

Uploads are spooled to the pod's `/tmp` (an `emptyDir`, see `tmp.sizeLimit`)
while hashing, then sent with multipart upload. With `redirectDownloads`, the
pods never stream large artifacts.

## Declaring stores

Declare stores in configuration (and the Helm chart's `blobStores`); they are
created or updated at startup:

```yaml
blobStores:
  - name: default
    type: file
    volume: {storageClass: gp3, accessMode: ReadWriteOnce, size: 200Gi}
  - name: shared
    type: file
    volume: {storageClass: efs-sc, accessMode: ReadWriteMany, size: 1Ti}
  - name: s3
    type: s3
    s3: {bucket: my-bucket, region: eu-west-2, redirectDownloads: true}
```

Stores can also be managed through the API (`/api/v1/blob-stores`), and later
through Terraform. `file` stores must live under `storage.allowedRoots`
(`/data` in the chart), so an API caller cannot point a store at arbitrary
paths. A store is checked to be reachable and writable before it is saved. It
cannot be deleted while repositories use it.

## Backups

* Postgres holds the metadata: back it up with your usual tooling.
* Blob stores: snapshot the volumes (EBS snapshots, AWS Backup for EFS) or
  enable S3 versioning and replication. Blobs are immutable and
  content-addressed, so an incremental copy is always consistent once the
  matching database backup is restored. Blobs without a database row are
  simply garbage-collected.
