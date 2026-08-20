#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
asset_source="${1:-}"
checksum_source="${2:-}"

if [[ -z "$asset_source" || -z "$checksum_source" ]]; then
  echo "usage: $0 <release.tgz|https-url> <release.tgz.sha256|https-url>" >&2
  exit 2
fi

verification_root="$(mktemp -d)"
cleanup() {
  rm -rf -- "$verification_root"
}
trap cleanup EXIT

fetch() {
  local source=$1
  local destination=$2
  case "$source" in
    https://github.com/*|https://objects.githubusercontent.com/*|https://release-assets.githubusercontent.com/*)
      curl --fail --silent --show-error --location "$source" --output "$destination"
      ;;
    http://*|https://*)
      echo "release input must use GitHub HTTPS hosting: $source" >&2
      return 1
      ;;
    *)
      cp -- "$source" "$destination"
      ;;
  esac
}

asset_name="$(basename "${asset_source%%\?*}")"
[[ "$asset_name" == *.tgz ]]
asset_file="$verification_root/$asset_name"
checksum_file="$verification_root/$asset_name.sha256"
fetch "$asset_source" "$asset_file"
fetch "$checksum_source" "$checksum_file"

read -r expected_hash expected_name extra <"$checksum_file"
expected_name="${expected_name#\*}"
if [[ ! "$expected_hash" =~ ^[0-9a-fA-F]{64}$ || "$expected_name" != "$asset_name" || -n "${extra:-}" ]]; then
  echo "invalid SHA-256 sidecar; expected '<64 hex>  $asset_name'" >&2
  exit 1
fi
expected_hash="${expected_hash,,}"
observed_hash="$(sha256sum "$asset_file" | awk '{print $1}')"
[[ "$observed_hash" == "$expected_hash" ]]
expected_plugin_version="${EXPECTED_PLUGIN_VERSION:-$(node -e 'process.stdout.write(require(process.argv[1]).version)' "$repo_root/package.json")}"

while IFS= read -r member; do
  case "$member" in
    /*|../*|*/../*|*/..)
      echo "unsafe archive path: $member" >&2
      exit 1
      ;;
  esac
done < <(tar -tzf "$asset_file")

tar -xOf "$asset_file" package/package.json >"$verification_root/package.json"
node - <<'NODE' "$verification_root/package.json" "$expected_plugin_version"
const manifest = require(process.argv[2])
const expectedVersion = process.argv[3]
if (manifest.name !== 'kaleidosphere-dsh-plugin') throw new Error(`unexpected package name: ${manifest.name}`)
if (manifest.version !== expectedVersion) throw new Error(`unexpected package version: ${manifest.version}`)
if (manifest.dsh?.bundle?.patch !== './cordis.patch.yml') throw new Error('missing exact dsh.bundle.patch')
if (manifest.scripts?.prepare !== undefined) throw new Error('release package must not declare prepare')
if (manifest.peerDependencies?.['@deepseek-ai/dsh-tools'] !== '0.1.0-rc.8') throw new Error('unexpected DSH tools peer')
NODE

required_members=(
  package/index.js
  package/cordis.patch.yml
  package/README.md
  package/LICENSE
  package/NOTICE
  package/VENDORED_MANIFEST.json
  package/THIRD_PARTY_MANIFEST.json
)
archive_members="$(tar -tzf "$asset_file")"
for required in "${required_members[@]}"; do
  grep -Fxq "$required" <<<"$archive_members"
done

if [[ "${VERIFY_RELEASE_SKIP_DSH:-0}" != 1 ]]; then
  expected_digests="$repo_root/test/expected-fixture-digests.json"
  if [[ "$expected_plugin_version" = '0.1.0-preview.1' ]]; then
    expected_digests="$repo_root/test/expected-fixture-digests-preview.1.json"
  fi
  DSH_EXPECT_ADVANCED_FEATURES="${VERIFY_RELEASE_EXPECT_ADVANCED_FEATURES:-0}" \
    DSH_EXPECTED_FIXTURE_DIGESTS="$expected_digests" \
    PLUGIN_SPEC="$asset_file" bash "$repo_root/scripts/test-dsh-rc8.sh"
fi

if [[ -n "${EVIDENCE_DIR:-}" ]]; then
  mkdir -p "$EVIDENCE_DIR"
  printf '%s  %s\n' "$observed_hash" "$asset_name" >"$EVIDENCE_DIR/release-asset.sha256"
  node - <<'NODE' "$EVIDENCE_DIR/release-verification.json" "$asset_name" "$observed_hash" "${VERIFY_RELEASE_SKIP_DSH:-0}"
const fs = require('node:fs')
const [output, asset, sha256, skipped] = process.argv.slice(2)
const report = {
  schemaVersion: 'kaleidosphere.dsh/release-verification/v1',
  asset,
  sha256,
  packageContract: 'PASS',
  dshRc8Lifecycle: skipped === '1' ? 'SKIPPED' : 'PASS',
}
fs.writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`)
NODE
fi

echo "RELEASE_ASSET_SHA256=$observed_hash"
echo "RELEASE_PACKAGE_CONTRACT=PASS"
if [[ "${VERIFY_RELEASE_SKIP_DSH:-0}" == 1 ]]; then
  echo "RELEASE_DSH_RC8_LIFECYCLE=SKIPPED"
else
  echo "RELEASE_DSH_RC8_LIFECYCLE=PASS"
fi
