#!/bin/sh
# Fake trivy CLI for tests: prints fixture reports depending on the target.
#   FAKE_SCAN_STATE/fail-N  fail the next N invocations (decremented)
#   FAKE_SCAN_SLEEP         seconds to sleep before answering
#   FAKE_SCAN_STATE/args    receives the arguments of each scan
here=$(cd "$(dirname "$0")" && pwd)
if [ "$1" = "--version" ]; then
  if [ "$2" = "--format" ]; then
    echo '{"Version":"0.99.0-fake","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-11-01T00:00:00Z"}}'
  else
    printf 'Version: 0.99.0-fake\nVulnerability DB:\n  Version: 2\n'
  fi
  exit 0
fi
if [ -n "$FAKE_SCAN_STATE" ]; then
  echo "$*" >> "$FAKE_SCAN_STATE/args"
  if [ -f "$FAKE_SCAN_STATE/fail" ]; then
    n=$(cat "$FAKE_SCAN_STATE/fail")
    if [ "$n" -gt 0 ]; then
      echo $((n - 1)) > "$FAKE_SCAN_STATE/fail"
      echo "FATAL simulated failure" >&2
      exit 1
    fi
  fi
fi
[ -n "$FAKE_SCAN_SLEEP" ] && sleep "$FAKE_SCAN_SLEEP"
case "$1" in
sbom)
  for f in "$@"; do sbom=$f; done
  [ -f "$sbom" ] || { echo "no sbom $sbom" >&2; exit 2; }
  grep -q '"specVersion": "1.5"' "$sbom" || { echo "not CycloneDX 1.5" >&2; exit 2; }
  if grep -q '"purl": "pkg:npm/lodash@4.17.20"' "$sbom"; then
    cat "$here/trivy-lodash.json"
  else
    echo '{"SchemaVersion":2,"Trivy":{"Version":"0.99.0-fake"},"Results":[]}'
  fi
  ;;
image)
  dir=$3
  [ "$2" = "--input" ] && [ -f "$dir/oci-layout" ] && [ -f "$dir/index.json" ] || { echo "not an OCI layout: $dir" >&2; exit 2; }
  # Every manifest in index.json, and everything it references, must exist.
  for d in $(grep -o 'sha256:[a-f0-9]\{64\}' "$dir/index.json"); do
    m="$dir/blobs/sha256/${d#sha256:}"
    [ -f "$m" ] || { echo "missing manifest $d" >&2; exit 3; }
    for r in $(grep -o 'sha256:[a-f0-9]\{64\}' "$m"); do
      [ -f "$dir/blobs/sha256/${r#sha256:}" ] || { echo "missing blob $r" >&2; exit 3; }
    done
  done
  cat "$here/trivy-image.json"
  ;;
*)
  echo "unexpected command $1" >&2; exit 2;;
esac
