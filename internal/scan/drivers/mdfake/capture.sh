#!/usr/bin/env bash
# Records MetaDefender Core's answers to the requests Entrepot makes, so they
# can be compared with the fixtures in fixtures/ (which follow the OpenAPI
# schemas). Sends three small files: a clean one, the EICAR anti-malware
# test file and a zip containing it. EICAR is harmless and assembled at
# runtime, so this repository never contains the signature.
#
#   MD_URL=https://metadefender:8008 MD_APIKEY=... MD_RULE="File process" ./capture.sh [out-dir]
#
# Needs curl, jq and zip. Writes JSON files to out-dir (default ./md-capture).
set -euo pipefail

: "${MD_URL:?set MD_URL to the MetaDefender Core REST API, e.g. https://metadefender:8008}"
MD_URL=${MD_URL%/}
OUT=${1:-./md-capture}
mkdir -p "$OUT"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

hdr=(-H "Accept: application/json")
[[ -n "${MD_APIKEY:-}" ]] && hdr+=(-H "apikey: $MD_APIKEY")
rule=()
[[ -n "${MD_RULE:-}" ]] && rule=(-H "rule: $(jq -rn --arg r "$MD_RULE" '$r|@uri')")
curl_md() { curl -sS --fail-with-body ${MD_CACERT:+--cacert "$MD_CACERT"} "${hdr[@]}" "$@"; }

echo "== readiness, version, rules"
curl_md "$MD_URL/readyz" | jq . > "$OUT/readyz.json" || true
curl_md "$MD_URL/version" | jq . > "$OUT/version.json"
curl_md "$MD_URL/file/rules" | jq . > "$OUT/rules.json"
jq -r '.version' "$OUT/version.json"

printf 'harmless test content %s\n' "$(date +%s)" > "$WORK/clean.txt"
# The EICAR test string, in two halves.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' > "$WORK/eicar.com"
(cd "$WORK" && zip -q eicar.zip eicar.com)

for f in clean.txt eicar.com eicar.zip; do
  name=${f%.*}-${f##*.}
  sum=$(sha256sum "$WORK/$f" | cut -d' ' -f1)
  echo "== $f ($sum)"
  # Hash lookup, as Entrepot does it (before and after the upload).
  curl_md -H "selfonly: true" "${rule[@]}" "$MD_URL/hash/$sum" > "$OUT/$name.hash-before.json" || true
  # Raw body upload with Content-Length (not multipart).
  curl_md -X POST -H "Content-Type: application/octet-stream" -H "filename: $f" "${rule[@]}" \
    --data-binary "@$WORK/$f" "$MD_URL/file" | jq . > "$OUT/$name.upload.json"
  id=$(jq -r '.data_id' "$OUT/$name.upload.json")
  for _ in $(seq 1 120); do
    curl_md "$MD_URL/file/$id?size=1" | jq . > "$OUT/$name.result.json"
    if [[ $(jq -r '.process_info.progress_percentage // 0' "$OUT/$name.result.json") == 100 &&
          $(jq -r '.process_info.result // ""' "$OUT/$name.result.json") != Processing ]]; then
      break
    fi
    sleep 1
  done
  jq -r '"   result: \(.process_info.result) / \(.scan_results.scan_all_result_a) (\(.scan_results.scan_all_result_i)), profile \(.process_info.profile)"' "$OUT/$name.result.json"
  curl_md "$MD_URL/file/$id/blocked-leaves" | jq . > "$OUT/$name.blocked-leaves.json" 2>/dev/null || true
  curl_md -H "selfonly: true" "${rule[@]}" "$MD_URL/hash/$sum" | jq . > "$OUT/$name.hash-after.json" || true
done

# What Entrepot reads from each result, for a quick comparison.
jq -s 'map({file: .file_info.display_name, data_id, sha256: .file_info.sha256, result: .process_info.result,
            code: .scan_results.scan_all_result_i, label: .scan_results.scan_all_result_a,
            blocked_reasons: .process_info.blocked_reasons, profile: .process_info.profile,
            outdated_data: .process_info.outdated_data, start_time: .scan_results.start_time,
            threats: [.scan_results.scan_details // {} | to_entries[] | select(.value.threat_found != "") | .value.threat_found]})' \
  "$OUT"/*.result.json > "$OUT/summary.json"
cat "$OUT/summary.json"
echo "Responses written to $OUT. Please send them (they contain no API key) if anything differs from the fixtures."
