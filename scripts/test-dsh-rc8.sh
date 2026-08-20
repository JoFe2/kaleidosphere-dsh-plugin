#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_root="$(mktemp -d)"
tools_root="${DSH_TOOLS_ROOT:-$run_root/tools}"
bin_root="$run_root/bin"
dsh_home="$run_root/home"
runtime_tmp="$run_root/runtime-tmp"
evidence_dir="${EVIDENCE_DIR:-$run_root/evidence}"
profile_name=ks-e2e
profile_dir="$dsh_home/profiles/$profile_name"
mkdir -p "$bin_root" "$dsh_home" "$runtime_tmp" "$evidence_dir"

cleanup() {
  if [[ -n "${dsh_pid:-}" ]] && kill -0 "$dsh_pid" 2>/dev/null; then kill -KILL "$dsh_pid" 2>/dev/null || true; fi
  if [[ "${KEEP_DSH_SMOKE:-0}" != 1 ]]; then rm -rf "$run_root"; fi
}
trap cleanup EXIT

corepack enable --install-directory "$bin_root"
if [[ -z "${DSH_TOOLS_ROOT:-}" ]]; then
  npm install --prefix "$tools_root" --no-audit --no-fund @deepseek-ai/dsh@0.1.0-rc.8 >/dev/null
fi
node -e 'const p=require(process.argv[1]); if(p.version!=="0.1.0-rc.8") process.exit(1)' "$tools_root/node_modules/@deepseek-ai/dsh/package.json"
export PATH="$tools_root/node_modules/.bin:$bin_root:$PATH"
export DSH_HOME="$dsh_home"
export TMPDIR="$runtime_tmp"

pack_json="$(cd "$repo_root" && npm pack --json --pack-destination "$run_root" --silent)"
pack_name="$(node -e 'const fs=require("fs");const x=JSON.parse(fs.readFileSync(0,"utf8"));process.stdout.write(x[0].filename)' <<<"$pack_json")"
package_file="$run_root/$pack_name"
plugin_spec="${PLUGIN_SPEC:-$package_file}"

dsh plugin --profile "$profile_name" add "$plugin_spec" >"$evidence_dir/add.log" 2>&1
dsh plugin --profile "$profile_name" add "$repo_root/test/dsh-probe-bundle" >"$evidence_dir/add-probe.log" 2>&1
dsh --profile "$profile_name" --dump-config >"$evidence_dir/dump-config-installed.txt"
rg -q '# == kaleidosphere-dsh-plugin' "$evidence_dir/dump-config-installed.txt"
rg -q 'id: kaleidosphere-dsh-plugin' "$evidence_dir/dump-config-installed.txt"

export KS_PROBE_ACTIVE="$evidence_dir/active.json"
export KS_PROBE_UNLOAD_REQUEST="$evidence_dir/request-unload"
export KS_PROBE_UNLOADED="$evidence_dir/unloaded.json"
export KS_PROBE_RELOAD_REQUEST="$evidence_dir/request-reload"
export KS_PROBE_RELOADED="$evidence_dir/reloaded.json"
export KS_PROBE_FAILURE="$evidence_dir/failure.json"
export KS_PROBE_DISPOSED="$evidence_dir/disposed.txt"
export KS_PROBE_MODE=hmr

dsh --profile "$profile_name" >"$evidence_dir/dsh.log" 2>&1 &
dsh_pid=$!

wait_for_file() {
  local file=$1
  for _ in $(seq 1 400); do
    [[ -f "$KS_PROBE_FAILURE" ]] && { cat "$KS_PROBE_FAILURE" >&2; return 1; }
    [[ -f "$file" ]] && return 0
    sleep 0.05
  done
  echo "timeout waiting for $file" >&2
  return 1
}

wait_for_file "$KS_PROBE_ACTIVE"
node - <<'NODE' "$KS_PROBE_ACTIVE" "$repo_root/test/expected-fixture-digests.json"
const active = require(process.argv[2])
const expected = require(process.argv[3])
if (active.state !== 'ACTIVE' || active.tools.length !== 6 || active.results.length !== 6) process.exit(1)
for (const result of active.results) {
  const action = result.name.replace('kaleidosphere_', '')
  const observed = {
    response: result.value?.response?.integrity?.digest,
    evidence: result.value?.evidence?.evidenceDigest,
  }
  if (JSON.stringify(observed) !== JSON.stringify(expected[action])) process.exit(1)
}
const analyze = active.results.find(result => result.name === 'kaleidosphere_analyze')
if (analyze?.value?.response?.result?.evidence?.snapshotSha256 !== '293a896156d8f6269c4ad33e8d632da653ea180d35a4ea5f390b0be52ce3e44a') process.exit(1)
NODE
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 1 ]]

printf '%s\n' '- id: kaleidosphere-dsh-plugin' '  disabled: true' >"$profile_dir/cordis.patch.yml"
: >"$KS_PROBE_UNLOAD_REQUEST"
wait_for_file "$KS_PROBE_UNLOADED"
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]

printf '[]\n' >"$profile_dir/cordis.patch.yml"
: >"$KS_PROBE_RELOAD_REQUEST"
wait_for_file "$KS_PROBE_RELOADED"
wait "$dsh_pid"
unset dsh_pid
[[ -f "$KS_PROBE_DISPOSED" ]]
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]

dsh plugin --profile "$profile_name" remove kaleidosphere-dsh-plugin >"$evidence_dir/remove.log" 2>&1
dsh --profile "$profile_name" --dump-config >"$evidence_dir/dump-config-removed.txt"
! rg -q '# == kaleidosphere-dsh-plugin|id: kaleidosphere-dsh-plugin' "$evidence_dir/dump-config-removed.txt"
node -e 'const p=require(process.argv[1]); if(p.dependencies?.["kaleidosphere-dsh-plugin"]||p.dsh.profile.bundles.includes("kaleidosphere-dsh-plugin")) process.exit(1)' "$profile_dir/package.json"

dsh plugin --profile "$profile_name" add "$plugin_spec" >"$evidence_dir/reinstall.log" 2>&1
dsh --profile "$profile_name" --dump-config >"$evidence_dir/dump-config-reinstalled.txt"
rg -q '# == kaleidosphere-dsh-plugin' "$evidence_dir/dump-config-reinstalled.txt"

export KS_PROBE_ACTIVE="$evidence_dir/active-reinstall.json"
export KS_PROBE_DISPOSED="$evidence_dir/disposed-reinstall.txt"
export KS_PROBE_MODE=oneshot
dsh --profile "$profile_name" >"$evidence_dir/dsh-reinstall.log" 2>&1 &
dsh_pid=$!
wait_for_file "$KS_PROBE_ACTIVE"
wait "$dsh_pid"
unset dsh_pid
[[ -f "$KS_PROBE_DISPOSED" ]]
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]

dsh plugin --profile "$profile_name" remove kaleidosphere-dsh-plugin kaleidosphere-dsh-probe >"$evidence_dir/remove-final.log" 2>&1
node -e 'const p=require(process.argv[1]); if(Object.keys(p.dependencies||{}).length||p.dsh.profile.bundles.some(x=>/kaleidosphere/.test(x))) process.exit(1)' "$profile_dir/package.json"

invalid_profile=ks-invalid
invalid_profile_dir="$dsh_home/profiles/$invalid_profile"
dsh plugin --profile "$invalid_profile" add "$plugin_spec" >"$evidence_dir/add-invalid.log" 2>&1
printf '%s\n' '- id: kaleidosphere-dsh-plugin' '  config:' '    source:' '      mode: remote' >"$invalid_profile_dir/cordis.patch.yml"
if dsh --profile "$invalid_profile" >"$evidence_dir/invalid-config.log" 2>&1; then
  echo 'invalid configuration unexpectedly loaded' >&2
  exit 1
fi
rg -q 'KS_DSH_SOURCE_MODE_INVALID' "$evidence_dir/invalid-config.log"
dsh plugin --profile "$invalid_profile" remove kaleidosphere-dsh-plugin >"$evidence_dir/remove-invalid.log" 2>&1
node -e 'const p=require(process.argv[1]); if(Object.keys(p.dependencies||{}).length||p.dsh.profile.bundles.some(x=>/kaleidosphere/.test(x))) process.exit(1)' "$invalid_profile_dir/package.json"

sha256sum "$package_file" >"$evidence_dir/package.sha256"
node - <<'NODE' "$evidence_dir"
const fs = require('fs')
const path = require('path')
const dir = process.argv[2]
const active = JSON.parse(fs.readFileSync(path.join(dir, 'active.json')))
const reinstall = JSON.parse(fs.readFileSync(path.join(dir, 'active-reinstall.json')))
const summary = {
  schemaVersion: 'kaleidosphere.dsh/exact-rc8-smoke/v1',
  dshVersion: '0.1.0-rc.8',
  install: 'PASS', dumpConfig: 'PASS', activeTools: active.tools,
  toolExecutions: active.results.length, hmrUnload: 'PASS', hmrReload: 'PASS',
  removal: 'PASS', reinstall: reinstall.results.length === 6 ? 'PASS' : 'FAIL', invalidConfig: 'PASS',
  residue: 'ZERO',
}
fs.writeFileSync(path.join(dir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`)
console.log(JSON.stringify(summary))
NODE
