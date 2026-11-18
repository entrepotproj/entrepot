#!/bin/sh
# Fake grype CLI for tests.
here=$(cd "$(dirname "$0")" && pwd)
if [ "$1" = "version" ]; then
  printf 'Application:         grype\nVersion:             0.86.1\nBuildDate:           2024-12-01\n'
  exit 0
fi
[ -n "$FAKE_SCAN_STATE" ] && echo "$*" >> "$FAKE_SCAN_STATE/grype-args"
case "$1" in
sbom:*)
  f=${1#sbom:}
  [ -f "$f" ] || { echo "no sbom" >&2; exit 2; }
  if grep -q '"purl": "pkg:npm/lodash@4.17.20"' "$f"; then cat "$here/grype-lodash.json"; else echo '{"matches":[],"descriptor":{"name":"grype","version":"0.86.1"}}'; fi
  ;;
oci-dir:*)
  d=${1#oci-dir:}
  [ -f "$d/index.json" ] || { echo "not a layout" >&2; exit 2; }
  echo '{"matches":[],"descriptor":{"name":"grype","version":"0.86.1"}}'
  ;;
*) echo "unexpected $1" >&2; exit 2;;
esac
