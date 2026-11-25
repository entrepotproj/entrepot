# Releasing

Entrepot uses [semantic versioning](https://semver.org) and
[release-please](https://github.com/googleapis/release-please). Versions and the
[CHANGELOG](CHANGELOG.md) come from the commit messages on `main`, so each merged PR needs a
[Conventional Commit](https://www.conventionalcommits.org) title.

A release publishes:

* the images `ghcr.io/entrepotproj/entrepot` and `ghcr.io/entrepotproj/entrepot-scanner`, tagged
  `X.Y.Z`, `X.Y` and `latest`;
* the Helm chart `oci://ghcr.io/entrepotproj/charts/entrepot`, version `X.Y.Z` (chart version and
  app version are the same);
* a GitHub release `vX.Y.Z` with the release notes and the chart `.tgz`.

The server reports its version in `entrepot version`, in its startup log and in
`GET /api/v1/system/info`.

## Commit messages

PRs are squash-merged, and the PR title becomes the commit message on `main`. The **PR title**
workflow checks it:

| Title | Changelog section | Version bump |
|---|---|---|
| `feat: …`, `feat(scope): …` | Features | minor |
| `fix: …` | Bug Fixes | patch |
| `perf: …` | Performance | patch |
| `deps: …` | Dependencies | patch |
| `revert: …` | Reverts | patch |
| `feat!: …`, or a `BREAKING CHANGE:` footer | ⚠ BREAKING CHANGES | major (minor before 1.0) |
| `docs:`, `refactor:`, `test:`, `build:`, `ci:`, `chore:`, `style:` | not listed | none |

Only the first five types trigger a release. Before 1.0, a breaking change bumps the minor
version (0.3.0 → 0.4.0), and features bump the minor version too.

## Cutting a release

1. release-please keeps a PR called **chore(main): release X.Y.Z** open. Every push to `main`
   updates it: the next version, its `CHANGELOG.md` entry, and the chart version in
   `deploy/helm/entrepot/Chart.yaml`.
2. To change the release notes, edit `CHANGELOG.md` in that PR, and its description, which becomes
   the GitHub release text. release-please rewrites both whenever `main` changes, so edit just
   before merging.
3. Merge the PR. release-please creates the tag `vX.Y.Z` and a **draft** GitHub release, then the
   [Release workflow](.github/workflows/release.yml) builds and pushes the images and the chart,
   attaches the chart, and publishes the release. The release never appears without its assets,
   which also keeps it compatible with GitHub's immutable releases.

### The first release

There is no release PR for 0.1.0: its notes are written by hand in `CHANGELOG.md`. Publish it once
the release setup is on `main`:

1. **Actions → Release → Run workflow**, on `main`, with tag `v0.1.0`.
2. The workflow checks that 0.1.0 is the version in `.release-please-manifest.json`, creates the
   tag and a draft release from the `## 0.1.0` section of `CHANGELOG.md`, and publishes as usual.

From then on, release-please takes over. Do this before merging any `feat:` or `fix:` PR.
Otherwise release-please opens a 0.1.0 release PR of its own, listing only those commits. If that
happens, close that PR after publishing 0.1.0 by hand.

## One-time repository settings

* **Settings → Actions → General → Workflow permissions:** enable *Allow GitHub Actions to create
  and approve pull requests*, so release-please can open its PR. If it is greyed out, enable it
  for the `entrepotproj` organisation first.
* **Settings → General → Pull Requests:** allow squash merging with *Default to pull request
  title*. Disable merge commits and rebase merging, so every change lands as one commit with a
  checked title.
* **Optional:** add a `RELEASE_PLEASE_TOKEN` secret (a GitHub App token or a fine-grained token
  with contents, issues and pull-requests write access). Without it, release-please uses
  `GITHUB_TOKEN`, and GitHub doesn't run workflows for PRs created with that token: CI doesn't run
  on the release PR. If branch protection requires status checks, you need the token, or an admin
  has to merge the release PR.

## When a release goes wrong

* **The publish job failed** (registry outage, expired credentials): fix the cause, then re-run the
  failed jobs of the **Release Please** run. Or run the **Release** workflow by hand with the tag:
  it picks up the draft release and carries on.
* **The tagged commit can't be built:** leave the draft release and its tag in place. Merge a
  `fix:` PR, then merge the next release PR (X.Y.Z+1). Delete the broken draft once that release
  is out.
* **Don't delete the tag of the latest release** or move a published tag. release-please uses the
  latest release's tag to find where the next changelog starts, and registries and caches may
  already have recorded the version.
