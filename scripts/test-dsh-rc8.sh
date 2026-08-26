#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_root="$(mktemp -d)"
if [[ -n "${EVIDENCE_DIR:-}" ]]; then
  # A prefilled caller directory is stale evidence preexists and is rejected.
  echo 'EVIDENCE_DIR must be empty; caller-supplied evidence is rejected to prevent stale evidence reuse' >&2
  exit 2
fi
run_id="$(basename "$run_root")"
tools_root="${DSH_TOOLS_ROOT:-$repo_root}"
bin_root="$run_root/bin"
dsh_home="$run_root/home"
runtime_tmp="$run_root/runtime-tmp"
evidence_dir="$run_root/evidence/$run_id"
advanced_features="${DSH_EXPECT_ADVANCED_FEATURES:-1}"
file_timeout_steps="${DSH_FILE_TIMEOUT_STEPS:-1200}"
profile_name=ks-e2e
profile_dir="$dsh_home/profiles/$profile_name"
# NR-1: own disposable package-manager state below the fresh run_root: every
# byte npm/pnpm/corepack writes during the lifecycle lands in these private
# paths (created by the mkdir below, deleted by the cleanup trap), so a
# constrained caller HOME — e.g. an empty read-only directory — stays
# untouched and no cache/home/store state leaks into the repository, the
# caller HOME or any persistent global directory.
npm_cache="$run_root/npm-cache"
pnpm_home="$run_root/pnpm-home"
xdg_cache="$run_root/xdg-cache"
xdg_state="$run_root/xdg-state"
xdg_config="$run_root/xdg-config"
corepack_home="$run_root/corepack"
mkdir -p "$bin_root" "$dsh_home" "$runtime_tmp" "$evidence_dir" "$npm_cache" "$pnpm_home" "$xdg_cache/pnpm" "$xdg_state/pnpm" "$xdg_config/pnpm" "$corepack_home"
export KS_PROBE_RUN_ID="$run_id"
# Constrained offline mode: seed the private state from a pre-provisioned
# read-only state root (layout: pnpm/, pnpm-cache/, corepack/, pnpm-state/,
# pnpm-config/) and resolve dependencies offline only. Without this hook the
# lifecycle keeps its existing behavior, still writing only below run_root.
if [[ -n "${DSH_PREPROVISIONED_STATE:-}" ]]; then
  state_root="$DSH_PREPROVISIONED_STATE"
  [[ -d "$state_root" ]] || { echo 'DSH_PREPROVISIONED_STATE must be a pre-provisioned state root directory' >&2; exit 2; }
  for state_part in pnpm pnpm-cache corepack pnpm-state pnpm-config; do
    [[ -d "$state_root/$state_part" ]] || { echo "DSH_PREPROVISIONED_STATE/$state_part is missing; pre-provisioned state root is incomplete" >&2; exit 2; }
  done
  cp -a "$state_root/pnpm/." "$pnpm_home/"
  cp -a "$state_root/pnpm-cache/." "$xdg_cache/pnpm/"
  cp -a "$state_root/corepack/." "$corepack_home/"
  cp -a "$state_root/pnpm-state/." "$xdg_state/pnpm/"
  cp -a "$state_root/pnpm-config/." "$xdg_config/pnpm/"
  # F2: cp -a preserves the read-only source modes; make the private copies
  # user-writable so pnpm/corepack can write their state. Only the run_root
  # destination trees are chmod'd — the read-only source state root is never
  # touched.
  chmod -R u+w "$pnpm_home" "$xdg_cache/pnpm" "$corepack_home" "$xdg_state/pnpm" "$xdg_config/pnpm"
  # F1: pnpm 11.24.0 ignores npm_config_offline; also export the exact
  # pnpm-recognized offline configuration so an incomplete pre-provisioned
  # store cannot silently fetch from a reachable registry. npm_config_offline
  # is kept so the npm portion (npm pack) stays explicitly offline too.
  export npm_config_offline=true
  export pnpm_config_offline=true
fi
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

# Route npm/pnpm/corepack writable state below run_root (NR-1): exported for
# every lifecycle subprocess (npm pack, the corepack shim and the pnpm
# forwarder) so the constrained caller HOME stays untouched.
export npm_config_cache="$npm_cache"
export PNPM_HOME="$pnpm_home"
export XDG_CACHE_HOME="$xdg_cache"
export XDG_STATE_HOME="$xdg_state"
export XDG_CONFIG_HOME="$xdg_config"
export COREPACK_HOME="$corepack_home"

corepack enable --install-directory "$bin_root"
node -e 'const p=require(process.argv[1]); if(p.version!=="0.1.0-rc.8") process.exit(1)' "$tools_root/node_modules/@deepseek-ai/dsh/package.json"
export PATH="$tools_root/node_modules/.bin:$bin_root:$PATH"
export DSH_HOME="$dsh_home"
export TMPDIR="$runtime_tmp"

# One exact flagged launcher: dsh_launch is a simple command array so a
# backgrounded launch execs node directly (dsh_pid stays the dsh process
# id) and every DSH launch runs the pinned rc.8 CLI entry with the required
# --expose-internals execArgv (Node 24 rejects that flag in NODE_OPTIONS).
dsh_entry="$tools_root/node_modules/@deepseek-ai/dsh/lib/bin.js"
[[ -f "$dsh_entry" ]]
dsh_launch=(node --expose-internals "$dsh_entry")

pack_json="$(cd "$repo_root" && npm pack --json --pack-destination "$run_root" --silent)"
pack_name="$(node -e 'const fs=require("fs");const x=JSON.parse(fs.readFileSync(0,"utf8"));process.stdout.write(x[0].filename)' <<<"$pack_json")"
package_file="$run_root/$pack_name"
plugin_spec="${PLUGIN_SPEC:-$package_file}"

"${dsh_launch[@]}" plugin --profile "$profile_name" add "$plugin_spec" >"$evidence_dir/add.log" 2>&1
"${dsh_launch[@]}" plugin --profile "$profile_name" add "$repo_root/test/dsh-probe-bundle" >"$evidence_dir/add-probe.log" 2>&1
"${dsh_launch[@]}" --profile "$profile_name" --dump-config >"$evidence_dir/dump-config-installed.txt"
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
fixture_digest_snapshot() {
  sha256sum "$repo_root/test/expected-fixture-digests.json" "$repo_root/test/expected-fixture-digests-preview.1.json"
}
fixture_digest_snapshot >"$evidence_dir/fixture-digests-before.json"
export KS_PROBE_LOCAL_SURFACE="$evidence_dir/local-surface.json"
export KS_PROBE_NEGATIVE_MATRIX="$evidence_dir/negative-matrix.json"

"${dsh_launch[@]}" --profile "$profile_name" >"$evidence_dir/dsh.log" 2>&1 &
dsh_pid=$!

wait_for_file() {
  local file=$1
  # evidence_dir is a fresh run-id directory; only files created below it can
  # be observed, and JSON evidence is independently bound by assert_run_bound_json.
  for _ in $(seq 1 "$file_timeout_steps"); do
    [[ -f "$KS_PROBE_FAILURE" ]] && { cat "$KS_PROBE_FAILURE" >&2; return 1; }
    [[ -f "$file" ]] && return 0
    sleep 0.05
  done
  echo "timeout waiting for $file" >&2
  [[ -f "$evidence_dir/dsh.log" ]] && tail -100 "$evidence_dir/dsh.log" >&2
  return 1
}

assert_run_bound_json() {
  node -e 'const fs=require("fs");const x=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));if(x.runId!==process.argv[2])throw new Error(`run binding mismatch for ${process.argv[1]}`)' "$1" "$run_id"
}

wait_for_file "$KS_PROBE_ACTIVE"
wait_for_file "$KS_PROBE_LOCAL_SURFACE"
wait_for_file "$KS_PROBE_NEGATIVE_MATRIX"
assert_run_bound_json "$KS_PROBE_ACTIVE"
assert_run_bound_json "$KS_PROBE_LOCAL_SURFACE"
assert_run_bound_json "$KS_PROBE_NEGATIVE_MATRIX"
node - <<'NODE' "$KS_PROBE_ACTIVE" "$expected_fixture_digests"
const active = require(process.argv[2])
const expected = require(process.argv[3])
if (active.state !== 'ACTIVE' || active.tools.length !== 6 || active.results.length !== 6) process.exit(1)
if (active.schemas.length !== 3 || active.invalid.length !== 3) process.exit(1)
const forbidden = new Set(['search', 'details', 'overview', 'kaleidosphere_search', 'kaleidosphere_details', 'kaleidosphere_overview', 'bi.object.search.read', 'bi.object.details.read', 'bi.database.overview.read'])
if (!Array.isArray(active.completeHostSchemaNames) || !Array.isArray(active.completeHostSchemaRecords) || active.completeHostSchemaRecords.length !== active.completeHostSchemaNames.length || typeof active.completeHostSchemaDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(active.completeHostSchemaDigest)) process.exit(1)
if (JSON.stringify(active.completeHostSchemaNames) !== JSON.stringify([...active.completeHostSchemaNames].sort()) || JSON.stringify(active.completeHostSchemaRecords.map(x => x.name).sort()) !== JSON.stringify(active.completeHostSchemaNames)) process.exit(1)
function denyMappedMetadata(value, key = '') {
  if (typeof value === 'string' && (key === '' || /(?:^|name|action|capabilit(?:y|ies)|tool|schema|identifier|id)$/i.test(key)) && forbidden.has(value)) process.exit(1)
  if (Array.isArray(value)) for (const item of value) denyMappedMetadata(item, key)
  else if (value && typeof value === 'object') for (const [childKey, childValue] of Object.entries(value)) denyMappedMetadata(childValue, childKey)
}
for (const record of active.completeHostSchemaRecords) denyMappedMetadata(record)
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
node - <<'NODE' "$KS_PROBE_LOCAL_SURFACE" "$KS_PROBE_NEGATIVE_MATRIX" "$dsh_pid"
const local = require(process.argv[2])
const matrix = require(process.argv[3])
const dshPid = Number(process.argv[4])
const expectedTools = [
  'kaleidosphere_analyze', 'kaleidosphere_discovery', 'kaleidosphere_plan',
  'kaleidosphere_preview', 'kaleidosphere_readback', 'kaleidosphere_status',
]
if (local.engine !== 'mssql' || local.actions.length !== 3) process.exit(1)
if (JSON.stringify(local.hostSurface.toolNames) !== JSON.stringify(expectedTools)) process.exit(1)
if (local.hostSurface.capabilities.some(x => ['search', 'details', 'overview'].includes(x.action))) process.exit(1)
if (local.hostSurface.capabilities.some(x => ['bi.object.search.read', 'bi.object.details.read', 'bi.database.overview.read'].includes(x.capabilityId) || ['Search', 'Details', 'Overview'].includes(x.name))) process.exit(1)
if (local.executionBinding?.boundary !== 'IN_PLUGIN_PROCESS_LOCAL_RUNTIME_NOT_HOST_TOOL') process.exit(1)
if (!Number.isSafeInteger(local.executionBinding?.processId) || local.executionBinding.processId !== dshPid) process.exit(1)
if (!Number.isSafeInteger(local.executionBinding?.generation) || local.hostSchemaNames?.join(',') !== expectedTools.join(',') || !Array.isArray(local.completeHostSchemaNames) || !expectedTools.every(name => local.completeHostSchemaNames.includes(name)) || typeof local.completeHostSchemaDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(local.completeHostSchemaDigest)) process.exit(1)
if (local.completeHostSchemaNames.filter(name => name.startsWith('kaleidosphere_')).sort().join(',') !== expectedTools.join(',')) process.exit(1)
if (local.completeHostSchemaNames.some(name => ['search', 'details', 'overview', 'kaleidosphere_search', 'kaleidosphere_details', 'kaleidosphere_overview', 'bi.object.search.read', 'bi.object.details.read', 'bi.database.overview.read'].includes(name))) process.exit(1)
if (matrix.engine !== 'mssql' || matrix.classes.length !== 7 || matrix.cases.length !== 16) process.exit(1)
if (matrix.executionBinding?.boundary !== 'IN_PLUGIN_PROCESS_LOCAL_RUNTIME_NOT_HOST_TOOL') process.exit(1)
if (matrix.executionBinding.processId !== local.executionBinding.processId || matrix.executionBinding.generation !== local.executionBinding.generation) process.exit(1)
if (matrix.hostSchemaNames?.join(',') !== expectedTools.join(',') || matrix.completeHostSchemaNames?.join(',') !== local.completeHostSchemaNames.join(',') || matrix.completeHostSchemaDigest !== local.completeHostSchemaDigest) process.exit(1)
if (matrix.completeHostSchemaNames.filter(name => name.startsWith('kaleidosphere_')).sort().join(',') !== expectedTools.join(',')) process.exit(1)
if (matrix.completeHostSchemaNames.some(name => ['search', 'details', 'overview', 'kaleidosphere_search', 'kaleidosphere_details', 'kaleidosphere_overview', 'bi.object.search.read', 'bi.object.details.read', 'bi.database.overview.read'].includes(name))) process.exit(1)
if (!matrix.cases.every(x => x.code.startsWith('KS_') || x.code.startsWith('DB_') || x.code === 'AbortError')) process.exit(1)
NODE
fixture_digest_snapshot >"$evidence_dir/fixture-digests-after.json"
cmp "$evidence_dir/fixture-digests-before.json" "$evidence_dir/fixture-digests-after.json"
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 1 ]]

printf '%s\n' '- id: kaleidosphere-dsh-plugin' '  disabled: true' >"$profile_dir/cordis.patch.yml"
: >"$KS_PROBE_UNLOAD_REQUEST"
wait_for_file "$KS_PROBE_UNLOADED"
assert_run_bound_json "$KS_PROBE_UNLOADED"
node - <<'NODE' "$KS_PROBE_UNLOADED"
const x = require(process.argv[2])
if (x.state !== 'UNLOADED' || !Array.isArray(x.tools) || x.tools.length !== 0 || JSON.stringify(x.hostSchemaNames) !== '[]') process.exit(1)
if (x.executionBinding?.boundary !== 'IN_PLUGIN_PROCESS_LOCAL_RUNTIME_NOT_HOST_TOOL') process.exit(1)
NODE
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]

printf '[]\n' >"$profile_dir/cordis.patch.yml"
: >"$KS_PROBE_RELOAD_REQUEST"
wait_for_file "$KS_PROBE_RELOADED"
assert_run_bound_json "$KS_PROBE_RELOADED"
node - <<'NODE' "$KS_PROBE_RELOADED"
const x = require(process.argv[2])
const expected = ['kaleidosphere_analyze', 'kaleidosphere_discovery', 'kaleidosphere_plan', 'kaleidosphere_preview', 'kaleidosphere_readback', 'kaleidosphere_status']
if (x.state !== 'RELOADED' || JSON.stringify(x.tools) !== JSON.stringify(expected) || JSON.stringify(x.hostSchemaNames) !== JSON.stringify(expected)) process.exit(1)
if (x.executionBinding?.boundary !== 'IN_PLUGIN_PROCESS_LOCAL_RUNTIME_NOT_HOST_TOOL') process.exit(1)
const status = x.status?.response?.result?.status ?? x.status?.result?.status ?? x.status?.status
if (typeof status !== 'string' || status.length === 0) process.exit(1)
NODE
wait_for_pid "$dsh_pid" 90 dsh
unset dsh_pid
[[ -f "$KS_PROBE_DISPOSED" ]]
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]

"${dsh_launch[@]}" plugin --profile "$profile_name" remove kaleidosphere-dsh-plugin >"$evidence_dir/remove.log" 2>&1
"${dsh_launch[@]}" --profile "$profile_name" --dump-config >"$evidence_dir/dump-config-removed.txt"
! grep -Eq '# == kaleidosphere-dsh-plugin|id: kaleidosphere-dsh-plugin' "$evidence_dir/dump-config-removed.txt"
node -e 'const p=require(process.argv[1]); if(p.dependencies?.["kaleidosphere-dsh-plugin"]||p.dsh.profile.bundles.includes("kaleidosphere-dsh-plugin")) process.exit(1)' "$profile_dir/package.json"

"${dsh_launch[@]}" plugin --profile "$profile_name" add "$plugin_spec" >"$evidence_dir/reinstall.log" 2>&1
"${dsh_launch[@]}" --profile "$profile_name" --dump-config >"$evidence_dir/dump-config-reinstalled.txt"
grep -Fq '# == kaleidosphere-dsh-plugin' "$evidence_dir/dump-config-reinstalled.txt"

export KS_PROBE_ACTIVE="$evidence_dir/active-reinstall.json"
export KS_PROBE_DISPOSED="$evidence_dir/disposed-reinstall.txt"
export KS_PROBE_MODE=oneshot
"${dsh_launch[@]}" --profile "$profile_name" >"$evidence_dir/dsh-reinstall.log" 2>&1 &
dsh_pid=$!
wait_for_file "$KS_PROBE_ACTIVE"
assert_run_bound_json "$KS_PROBE_ACTIVE"
wait_for_pid "$dsh_pid" 90 dsh
unset dsh_pid
[[ -f "$KS_PROBE_DISPOSED" ]]
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]
export KS_PROBE_RESIDUE=ZERO

"${dsh_launch[@]}" plugin --profile "$profile_name" remove kaleidosphere-dsh-plugin kaleidosphere-dsh-probe >"$evidence_dir/remove-final.log" 2>&1
node -e 'const p=require(process.argv[1]); if(Object.keys(p.dependencies||{}).length||p.dsh.profile.bundles.some(x=>/kaleidosphere/.test(x))) process.exit(1)' "$profile_dir/package.json"

invalid_profile=ks-invalid
invalid_profile_dir="$dsh_home/profiles/$invalid_profile"
"${dsh_launch[@]}" plugin --profile "$invalid_profile" add "$plugin_spec" >"$evidence_dir/add-invalid.log" 2>&1
printf '%s\n' '- id: kaleidosphere-dsh-plugin' '  config:' '    source:' '      mode: remote' >"$invalid_profile_dir/cordis.patch.yml"
if "${dsh_launch[@]}" --profile "$invalid_profile" >"$evidence_dir/invalid-config.log" 2>&1; then
  echo 'invalid configuration unexpectedly loaded' >&2
  exit 1
fi
grep -Fq 'KS_DSH_SOURCE_MODE_INVALID' "$evidence_dir/invalid-config.log"
"${dsh_launch[@]}" plugin --profile "$invalid_profile" remove kaleidosphere-dsh-plugin >"$evidence_dir/remove-invalid.log" 2>&1
node -e 'const p=require(process.argv[1]); if(Object.keys(p.dependencies||{}).length||p.dsh.profile.bundles.some(x=>/kaleidosphere/.test(x))) process.exit(1)' "$invalid_profile_dir/package.json"

if [[ "$advanced_features" = 1 ]]; then
toggled_profile=ks-toggled
toggled_profile_dir="$dsh_home/profiles/$toggled_profile"
"${dsh_launch[@]}" plugin --profile "$toggled_profile" add "$plugin_spec" >"$evidence_dir/add-toggled.log" 2>&1
"${dsh_launch[@]}" plugin --profile "$toggled_profile" add "$repo_root/test/dsh-probe-bundle" >"$evidence_dir/add-toggled-probe.log" 2>&1
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
"${dsh_launch[@]}" --profile "$toggled_profile" >"$evidence_dir/dsh-toggled.log" 2>&1 &
dsh_pid=$!
wait_for_file "$KS_PROBE_ACTIVE"
assert_run_bound_json "$KS_PROBE_ACTIVE"
wait_for_pid "$dsh_pid" 90 dsh
unset dsh_pid KS_PROBE_EXPECTED_TOOL_NAMES
node -e 'const x=require(process.argv[1]); if(x.tools.length!==5||x.tools.includes("kaleidosphere_preview")||x.results.length!==0) process.exit(1)' "$KS_PROBE_ACTIVE"
[[ -f "$KS_PROBE_DISPOSED" ]]
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]
"${dsh_launch[@]}" plugin --profile "$toggled_profile" remove kaleidosphere-dsh-plugin kaleidosphere-dsh-probe >"$evidence_dir/remove-toggled.log" 2>&1
node -e 'const p=require(process.argv[1]); if(Object.keys(p.dependencies||{}).length||p.dsh.profile.bundles.some(x=>/kaleidosphere/.test(x))) process.exit(1)' "$toggled_profile_dir/package.json"

external_ready="$run_root/external.url"
external_log="$evidence_dir/external-stub-requests.jsonl"
# bounded external stub: loopback-only and request-log bounded below
node "$repo_root/scripts/ks-external-stub.mjs" --ready "$external_ready" --log "$external_log" \
  >"$evidence_dir/external-stub.stdout.log" 2>"$evidence_dir/external-stub.stderr.log" &
external_pid=$!
wait_for_file "$external_ready"
external_url="$(<"$external_ready")"
external_profile=ks-external
external_profile_dir="$dsh_home/profiles/$external_profile"
"${dsh_launch[@]}" plugin --profile "$external_profile" add "$plugin_spec" >"$evidence_dir/add-external.log" 2>&1
"${dsh_launch[@]}" plugin --profile "$external_profile" add "$repo_root/test/dsh-probe-bundle" >"$evidence_dir/add-external-probe.log" 2>&1
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
"${dsh_launch[@]}" --profile "$external_profile" >"$evidence_dir/dsh-external.log" 2>&1 &
dsh_pid=$!
wait_for_file "$KS_PROBE_ACTIVE"
assert_run_bound_json "$KS_PROBE_ACTIVE"
wait_for_pid "$dsh_pid" 90 dsh
unset dsh_pid KS_PROBE_EXPECTED_TOOL_NAMES
node -e 'const x=require(process.argv[1]); if(x.tools.length!==1||x.results.length!==1||x.results[0].value?.response?.result?.status!=="EXTERNAL_STUB_READY") process.exit(1)' "$KS_PROBE_ACTIVE"
[[ -f "$KS_PROBE_DISPOSED" ]]
[[ "$(find "$runtime_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]
node -e 'const fs=require("fs");const x=fs.readFileSync(process.argv[1],"utf8").trim().split("\n").map(JSON.parse);if(x.length!==2||x[0].path!=="/v2/capabilities"||x[1].path!=="/v2/intents"||x[1].action!=="status"||x.some(r=>r.path.includes("/v1/")||r.action&&r.action!=="status"))process.exit(1)' "$external_log"
kill -TERM "$external_pid"
wait "$external_pid"
unset external_pid
"${dsh_launch[@]}" plugin --profile "$external_profile" remove kaleidosphere-dsh-plugin kaleidosphere-dsh-probe >"$evidence_dir/remove-external.log" 2>&1
node -e 'const p=require(process.argv[1]); if(Object.keys(p.dependencies||{}).length||p.dsh.profile.bundles.some(x=>/kaleidosphere/.test(x))) process.exit(1)' "$external_profile_dir/package.json"
fi

sha256sum "$package_file" >"$evidence_dir/package.sha256"
node - <<'NODE' "$evidence_dir" "$advanced_features"
const fs = require('fs')
const path = require('path')
const dir = process.argv[2]
const advanced = process.argv[3] === '1'
const runId = process.env.KS_PROBE_RUN_ID
if (typeof runId !== 'string' || runId.length === 0) throw new Error('missing fresh run id')
const active = JSON.parse(fs.readFileSync(path.join(dir, 'active.json')))
const reinstall = JSON.parse(fs.readFileSync(path.join(dir, 'active-reinstall.json')))
const unloaded = JSON.parse(fs.readFileSync(path.join(dir, 'unloaded.json')))
const reloaded = JSON.parse(fs.readFileSync(path.join(dir, 'reloaded.json')))
for (const [name, evidence] of Object.entries({ active, reinstall, unloaded, reloaded })) {
  if (evidence.runId !== runId) throw new Error(`stale or foreign ${name} evidence`)
}
const expectedTools = ['kaleidosphere_analyze', 'kaleidosphere_discovery', 'kaleidosphere_plan', 'kaleidosphere_preview', 'kaleidosphere_readback', 'kaleidosphere_status']
if (unloaded.state !== 'UNLOADED' || unloaded.tools.length !== 0) throw new Error('invalid unloaded lifecycle evidence')
if (reloaded.state !== 'RELOADED' || JSON.stringify(reloaded.tools) !== JSON.stringify(expectedTools)) throw new Error('invalid reloaded lifecycle evidence')
const reloadedStatus = reloaded.status?.response?.result?.status ?? reloaded.status?.result?.status ?? reloaded.status?.status
if (typeof reloadedStatus !== 'string' || reloadedStatus.length === 0) throw new Error('missing reloaded status')
if (process.env.KS_PROBE_RESIDUE !== 'ZERO') throw new Error('residue was not proven zero')
const summary = {
  runId,
  schemaVersion: 'kaleidosphere.dsh/exact-rc8-smoke/v1',
  dshVersion: '0.1.0-rc.8',
  install: 'PASS', dumpConfig: 'PASS', activeTools: active.tools,
  toolExecutions: active.results.length, hmrUnload: unloaded.state === 'UNLOADED' && unloaded.tools.length === 0 ? 'PASS' : 'FAIL', hmrReload: reloaded.state === 'RELOADED' && JSON.stringify(reloaded.tools) === JSON.stringify(expectedTools) && typeof reloadedStatus === 'string' ? 'PASS' : 'FAIL',
  removal: 'PASS', reinstall: reinstall.results.length === 6 ? 'PASS' : 'FAIL', invalidConfig: 'PASS',
  intentExposure: advanced ? '5_OF_6_REAL_HOST_PASS' : 'NOT_EXPECTED_FOR_ARTIFACT',
  externalBinding: advanced ? 'ATTESTED_LOOPBACK_V2_PASS' : 'NOT_EXPECTED_FOR_ARTIFACT',
  externalNonClaim: advanced ? 'P3C-EXTERNAL-LOCAL-ONLY' : 'NOT_EXPECTED_FOR_ARTIFACT',
  residue: process.env.KS_PROBE_RESIDUE === 'ZERO' ? 'ZERO' : 'FAIL',
}
if (!(summary.hmrUnload === 'PASS' && summary.hmrReload === 'PASS' && summary.residue === 'ZERO')) throw new Error('lifecycle summary cannot claim PASS')
fs.writeFileSync(path.join(dir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`)
console.log(JSON.stringify(summary))
NODE
