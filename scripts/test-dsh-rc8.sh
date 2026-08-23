#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_root="$(mktemp -d)"
tools_root="${DSH_TOOLS_ROOT:-$repo_root}"
bin_root="$run_root/bin"
dsh_home="$run_root/home"
runtime_tmp="$run_root/runtime-tmp"
evidence_dir="${EVIDENCE_DIR:-$run_root/evidence}"
advanced_features="${DSH_EXPECT_ADVANCED_FEATURES:-1}"
file_timeout_steps="${DSH_FILE_TIMEOUT_STEPS:-1200}"
profile_name=ks-e2e
profile_dir="$dsh_home/profiles/$profile_name"
mkdir -p "$bin_root" "$dsh_home" "$runtime_tmp" "$evidence_dir"
[[ "$advanced_features" = 0 || "$advanced_features" = 1 ]]

cleanup() {
  if [[ -n "${dsh_pid:-}" ]] && kill -0 "$dsh_pid" 2>/dev/null; then kill -KILL "$dsh_pid" 2>/dev/null || true; fi
  if [[ -n "${external_pid:-}" ]] && kill -0 "$external_pid" 2>/dev/null; then
    kill -TERM "$external_pid" 2>/dev/null || true
    wait "$external_pid" 2>/dev/null || true
  fi
  if [[ "${KEEP_DSH_SMOKE:-0}" != 1 ]]; then rm -rf "$run_root"; fi
}
trap cleanup EXIT

wait_for_pid() {
  local pid=$1 seconds=$2 label=$3
  if ! timeout "$seconds" tail --pid="$pid" -f /dev/null; then
    echo "timeout waiting for $label pid=$pid after ${seconds}s" >&2
    return 124
  fi
  wait "$pid"
}

corepack enable --install-directory "$bin_root"
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
grep -Fq '# == kaleidosphere-dsh-plugin' "$evidence_dir/dump-config-installed.txt"
grep -Fq 'id: kaleidosphere-dsh-plugin' "$evidence_dir/dump-config-installed.txt"

export KS_PROBE_ACTIVE="$evidence_dir/active.json"
export KS_PROBE_UNLOAD_REQUEST="$evidence_dir/request-unload"
export KS_PROBE_UNLOADED="$evidence_dir/unloaded.json"
export KS_PROBE_RELOAD_REQUEST="$evidence_dir/request-reload"
export KS_PROBE_RELOADED="$evidence_dir/reloaded.json"
export KS_PROBE_FAILURE="$evidence_dir/failure.json"
export KS_PROBE_DISPOSED="$evidence_dir/disposed.txt"
export KS_PROBE_MODE=hmr
expected_fixture_digests="${DSH_EXPECTED_FIXTURE_DIGESTS:-$repo_root/test/expected-fixture-digests.json}"

dsh --profile "$profile_name" >"$evidence_dir/dsh.log" 2>&1 &
dsh_pid=$!

wait_for_file() {
  local file=$1
  for _ in $(seq 1 "$file_timeout_steps"); do
    [[ -f "$KS_PROBE_FAILURE" ]] && { cat "$KS_PROBE_FAILURE" >&2; return 1; }
    [[ -f "$file" ]] && return 0
    sleep 0.05
  done
  echo "timeout waiting for $file" >&2
  [[ -f "$evidence_dir/dsh.log" ]] && tail -100 "$evidence_dir/dsh.log" >&2
  return 1
}

wait_for_file "$KS_PROBE_ACTIVE"
node - <<'NODE' "$KS_PROBE_ACTIVE" "$expected_fixture_digests"
const active = require(process.argv[2])
const expected = require(process.argv[3])
if (active.state !== 'ACTIVE' || active.tools.length !== 6 || active.results.length !== 6) process.exit(1)
if (active.schemas.length !== 3 || active.invalid.length !== 3) process.exit(1)
for (const schema of active.schemas) {
  const parameters = schema.parameters
  if (parameters?.type !== 'object' || typeof parameters.properties !== 'object') process.exit(1)
  if (!Array.isArray(parameters.required) || parameters.required.length === 0) process.exit(1)
  for (const property of Object.values(parameters.properties)) {
    if (Object.hasOwn(property, 'required') || property.type === 'json') process.exit(1)
  }
}
for (const result of active.invalid) {
  const serialized = JSON.stringify(result)
  if (!result.isError || !serialized.includes('INVALID_ARGS') || serialized.includes('EXTERNAL_BI_REQUEST_SURFACE_DENIED')) process.exit(1)
}
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
wait_for_pid "$dsh_pid" 90 dsh
unset dsh_pid
[[ -f "$KS_PROBE_DISPOSED" ]]
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]

dsh plugin --profile "$profile_name" remove kaleidosphere-dsh-plugin >"$evidence_dir/remove.log" 2>&1
dsh --profile "$profile_name" --dump-config >"$evidence_dir/dump-config-removed.txt"
! grep -Eq '# == kaleidosphere-dsh-plugin|id: kaleidosphere-dsh-plugin' "$evidence_dir/dump-config-removed.txt"
node -e 'const p=require(process.argv[1]); if(p.dependencies?.["kaleidosphere-dsh-plugin"]||p.dsh.profile.bundles.includes("kaleidosphere-dsh-plugin")) process.exit(1)' "$profile_dir/package.json"

dsh plugin --profile "$profile_name" add "$plugin_spec" >"$evidence_dir/reinstall.log" 2>&1
dsh --profile "$profile_name" --dump-config >"$evidence_dir/dump-config-reinstalled.txt"
grep -Fq '# == kaleidosphere-dsh-plugin' "$evidence_dir/dump-config-reinstalled.txt"

export KS_PROBE_ACTIVE="$evidence_dir/active-reinstall.json"
export KS_PROBE_DISPOSED="$evidence_dir/disposed-reinstall.txt"
export KS_PROBE_MODE=oneshot
dsh --profile "$profile_name" >"$evidence_dir/dsh-reinstall.log" 2>&1 &
dsh_pid=$!
wait_for_file "$KS_PROBE_ACTIVE"
wait_for_pid "$dsh_pid" 90 dsh
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
grep -Fq 'KS_DSH_SOURCE_MODE_INVALID' "$evidence_dir/invalid-config.log"
dsh plugin --profile "$invalid_profile" remove kaleidosphere-dsh-plugin >"$evidence_dir/remove-invalid.log" 2>&1
node -e 'const p=require(process.argv[1]); if(Object.keys(p.dependencies||{}).length||p.dsh.profile.bundles.some(x=>/kaleidosphere/.test(x))) process.exit(1)' "$invalid_profile_dir/package.json"

if [[ "$advanced_features" = 1 ]]; then
toggled_profile=ks-toggled
toggled_profile_dir="$dsh_home/profiles/$toggled_profile"
dsh plugin --profile "$toggled_profile" add "$plugin_spec" >"$evidence_dir/add-toggled.log" 2>&1
dsh plugin --profile "$toggled_profile" add "$repo_root/test/dsh-probe-bundle" >"$evidence_dir/add-toggled-probe.log" 2>&1
printf '%s\n' \
  '- id: kaleidosphere-dsh-plugin' \
  '  config:' \
  '    source:' \
  '      mode: fixture' \
  '    expose:' \
  '      preview: false' \
  >"$toggled_profile_dir/cordis.patch.yml"
export KS_PROBE_ACTIVE="$evidence_dir/active-toggled.json"
export KS_PROBE_DISPOSED="$evidence_dir/disposed-toggled.txt"
export KS_PROBE_MODE=inventory
export KS_PROBE_EXPECTED_TOOL_NAMES='kaleidosphere_status,kaleidosphere_discovery,kaleidosphere_analyze,kaleidosphere_plan,kaleidosphere_readback'
dsh --profile "$toggled_profile" >"$evidence_dir/dsh-toggled.log" 2>&1 &
dsh_pid=$!
wait_for_file "$KS_PROBE_ACTIVE"
wait_for_pid "$dsh_pid" 90 dsh
unset dsh_pid KS_PROBE_EXPECTED_TOOL_NAMES
node -e 'const x=require(process.argv[1]); if(x.tools.length!==5||x.tools.includes("kaleidosphere_preview")||x.results.length!==0) process.exit(1)' "$KS_PROBE_ACTIVE"
[[ -f "$KS_PROBE_DISPOSED" ]]
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]
dsh plugin --profile "$toggled_profile" remove kaleidosphere-dsh-plugin kaleidosphere-dsh-probe >"$evidence_dir/remove-toggled.log" 2>&1
node -e 'const p=require(process.argv[1]); if(Object.keys(p.dependencies||{}).length||p.dsh.profile.bundles.some(x=>/kaleidosphere/.test(x))) process.exit(1)' "$toggled_profile_dir/package.json"

external_ready="$run_root/external.url"
external_log="$evidence_dir/external-stub-requests.jsonl"
node "$repo_root/scripts/ks-external-stub.mjs" --ready "$external_ready" --log "$external_log" \
  >"$evidence_dir/external-stub.stdout.log" 2>"$evidence_dir/external-stub.stderr.log" &
external_pid=$!
wait_for_file "$external_ready"
external_url="$(<"$external_ready")"
external_profile=ks-external
external_profile_dir="$dsh_home/profiles/$external_profile"
dsh plugin --profile "$external_profile" add "$plugin_spec" >"$evidence_dir/add-external.log" 2>&1
dsh plugin --profile "$external_profile" add "$repo_root/test/dsh-probe-bundle" >"$evidence_dir/add-external-probe.log" 2>&1
printf '%s\n' \
  '- id: kaleidosphere-dsh-plugin' \
  '  config:' \
  '    runtimeMode: external' \
  '    external:' \
  "      baseUrl: $external_url" \
  '    expose:' \
  '      status: true' \
  '      discovery: false' \
  '      analyze: false' \
  '      plan: false' \
  '      preview: false' \
  '      readback: false' \
  >"$external_profile_dir/cordis.patch.yml"
export KS_PROBE_ACTIVE="$evidence_dir/active-external.json"
export KS_PROBE_DISPOSED="$evidence_dir/disposed-external.txt"
export KS_PROBE_MODE=status
export KS_PROBE_EXPECTED_TOOL_NAMES='kaleidosphere_status'
dsh --profile "$external_profile" >"$evidence_dir/dsh-external.log" 2>&1 &
dsh_pid=$!
wait_for_file "$KS_PROBE_ACTIVE"
wait_for_pid "$dsh_pid" 90 dsh
unset dsh_pid KS_PROBE_EXPECTED_TOOL_NAMES
node -e 'const x=require(process.argv[1]); if(x.tools.length!==1||x.results.length!==1||x.results[0].value?.response?.result?.status!=="EXTERNAL_STUB_READY") process.exit(1)' "$KS_PROBE_ACTIVE"
[[ -f "$KS_PROBE_DISPOSED" ]]
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]
node -e 'const fs=require("fs");const x=fs.readFileSync(process.argv[1],"utf8").trim().split("\n").map(JSON.parse);if(x.length!==2||x[0].path!=="/v2/capabilities"||x[1].path!=="/v2/intents"||x[1].action!=="status")process.exit(1)' "$external_log"
kill -TERM "$external_pid"
wait "$external_pid"
unset external_pid
dsh plugin --profile "$external_profile" remove kaleidosphere-dsh-plugin kaleidosphere-dsh-probe >"$evidence_dir/remove-external.log" 2>&1
node -e 'const p=require(process.argv[1]); if(Object.keys(p.dependencies||{}).length||p.dsh.profile.bundles.some(x=>/kaleidosphere/.test(x))) process.exit(1)' "$external_profile_dir/package.json"
fi

sha256sum "$package_file" >"$evidence_dir/package.sha256"
node - <<'NODE' "$evidence_dir" "$advanced_features"
const fs = require('fs')
const path = require('path')
const dir = process.argv[2]
const advanced = process.argv[3] === '1'
const active = JSON.parse(fs.readFileSync(path.join(dir, 'active.json')))
const reinstall = JSON.parse(fs.readFileSync(path.join(dir, 'active-reinstall.json')))
const summary = {
  schemaVersion: 'kaleidosphere.dsh/exact-rc8-smoke/v1',
  dshVersion: '0.1.0-rc.8',
  install: 'PASS', dumpConfig: 'PASS', activeTools: active.tools,
  toolExecutions: active.results.length, hmrUnload: 'PASS', hmrReload: 'PASS',
  removal: 'PASS', reinstall: reinstall.results.length === 6 ? 'PASS' : 'FAIL', invalidConfig: 'PASS',
  intentExposure: advanced ? '5_OF_6_REAL_HOST_PASS' : 'NOT_EXPECTED_FOR_ARTIFACT',
  externalBinding: advanced ? 'ATTESTED_LOOPBACK_V2_PASS' : 'NOT_EXPECTED_FOR_ARTIFACT',
  residue: 'ZERO',
}
fs.writeFileSync(path.join(dir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`)
console.log(JSON.stringify(summary))
NODE
