# Releasing

Releases are cut automatically by
[semantic-release](https://semantic-release.gitbook.io/) from the commit
messages on `main`. Nobody tags by hand.

Every push to `main` runs the `Release` workflow. It looks at the commits
since the last `v*` tag and, if any of them warrants a release, it:

1. works out the next version and pushes the tag `vX.Y.Z`;
2. creates the GitHub release, with notes generated from the commits;
3. builds and pushes the server and scanner images
   (`ghcr.io/entrepotproj/entrepot`, `…/entrepot-scanner`) as `X.Y.Z`, `X.Y`
   and `latest`;
4. packages the Helm chart as `X.Y.Z`, pushes it to
   `oci://ghcr.io/entrepotproj/charts` and attaches it to the release.

## Commit messages

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
The type decides the release:

| Commit | Example | Release |
|---|---|---|
| `fix:` or `perf:` | `fix(web): show the current bucket` | patch (`0.1.0` → `0.1.1`) |
| `feat:` | `feat(dashboard): list vulnerable components` | minor (`0.1.0` → `0.2.0`) |
| `!` after the type, or a `BREAKING CHANGE:` footer | `feat(api)!: drop the v0 search endpoint` | major (`0.1.0` → `1.0.0`) |
| anything else (`docs:`, `chore:`, `ci:`, `test:`, `refactor:`, …) | `docs(scanning): document search filters` | none |

The highest type among the new commits wins, and a push with no releasing
commit publishes nothing. When a pull request is squash-merged, its title
becomes the commit message, so the title must follow the convention; with a
merge commit, the commits on the branch are what count.

## Notes

* semantic-release has no special handling of `0.x`: a breaking change always
  bumps to the next major, so the first one releases `1.0.0`.
* With no `v*` tag in the repository, the first release is `1.0.0`. To start
  from another version, push that tag (for example `v0.1.0`) before the first
  run.
* The configuration is `.releaserc.json`; the tool versions are pinned in
  `.github/workflows/release.yml`.
