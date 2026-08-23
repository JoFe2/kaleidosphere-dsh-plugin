#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_root="$(mktemp -d)"
tools_root="${DSH_TOOLS_ROOT:-$repo_root}"
bin_root="$run_root/bin"
homes_root="$run_root/homes"
runtime_tmp="$run_root/runtime-tmp"
evidence_dir="${EVIDENCE_DIR:-$run_root/evidence}"
expected_plugin_sha="${EXPECTED_PLUGIN_SHA256:-}"
plugin_artifact_label="${PLUGIN_ARTIFACT_LABEL:-local-candidate}"
file_timeout_steps="${DSH_FILE_TIMEOUT_STEPS:-1200}"
mkdir -p "$bin_root" "$homes_root" "$runtime_tmp" "$evidence_dir"

cleanup() {
  if [[ -n "${stub_pid:-}" ]] && kill -0 "$stub_pid" 2>/dev/null; then
    kill -TERM "$stub_pid" 2>/dev/null || true
    wait "$stub_pid" 2>/dev/null || true
  fi
  if [[ "${KEEP_DSH_AGENT_SMOKE:-0}" != 1 ]]; then rm -rf -- "$run_root"; fi
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
node -e 'const p=require(process.argv[1]); if(p.version!=="0.1.0-rc.8") process.exit(1)' \
  "$tools_root/node_modules/@deepseek-ai/dsh/package.json"
export PATH="$tools_root/node_modules/.bin:$bin_root:$PATH"

if [[ -n "${PLUGIN_SPEC:-}" ]]; then
  plugin_name="$(basename "$PLUGIN_SPEC")"
  plugin_file="$run_root/$plugin_name"
  cp -- "$PLUGIN_SPEC" "$plugin_file"
else
  pack_json="$(cd "$repo_root" && npm pack --json --pack-destination "$run_root" --silent)"
  plugin_name="$(node -e 'const fs=require("fs");const x=JSON.parse(fs.readFileSync(0,"utf8"));process.stdout.write(x[0].filename)' <<<"$pack_json")"
  plugin_file="$run_root/$plugin_name"
fi
observed_sha="$(sha256sum "$plugin_file" | awk '{print $1}')"
if [[ -n "$expected_plugin_sha" ]]; then [[ "$observed_sha" = "$expected_plugin_sha" ]]; fi
printf '%s  %s\n' "$observed_sha" "$plugin_name" >"$evidence_dir/plugin-artifact.sha256"

stub_ready="$run_root/stub.url"
stub_log="$evidence_dir/model-stub-requests.jsonl"
node "$repo_root/scripts/dsh-agent-stub.mjs" --ready "$stub_ready" --log "$stub_log" \
  >"$evidence_dir/model-stub.stdout.log" 2>"$evidence_dir/model-stub.stderr.log" &
stub_pid=$!
for _ in $(seq 1 "$file_timeout_steps"); do
  [[ -f "$stub_ready" ]] && break
  kill -0 "$stub_pid" 2>/dev/null || { echo 'model stub stopped before readiness' >&2; exit 1; }
  sleep 0.05
done
[[ -f "$stub_ready" ]]
stub_url="$(<"$stub_ready")"

home_for() {
  printf '%s/%s' "$homes_root" "$1"
}

install_plugin() {
  local home_key=$1
  DSH_HOME="$(home_for "$home_key")" dsh plugin --profile headless add "$plugin_file" \
    >"$evidence_dir/$home_key-add.log" 2>&1
}

run_agent() {
  local scenario=$1
  local home_key=$2
  local prompt=$3
  local scenario_tmp="$runtime_tmp/$scenario"
  mkdir -p "$scenario_tmp"
  DSH_HOME="$(home_for "$home_key")" TMPDIR="$scenario_tmp" \
    DEEPSEEK_API_KEY='local-deterministic-stub' \
    DEEPSEEK_BASE_URL="$stub_url/$scenario" \
    timeout "${DSH_AGENT_TIMEOUT_SECONDS:-90}" dsh --profile headless "$prompt" \
    >"$evidence_dir/$scenario.out" 2>"$evidence_dir/$scenario.err"
  [[ "$(find "$scenario_tmp" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]
}

natural_prompt='Analyze the configured KaleidoSphere database and report its engine and snapshot digest.'

run_agent no-plugin no-plugin "$natural_prompt"
grep -Fq 'KS_AGENT_UNAVAILABLE scenario=no-plugin' "$evidence_dir/no-plugin.out"

install_plugin happy
DSH_HOME="$(home_for happy)" dsh --profile headless --dump-config >"$evidence_dir/happy-dump-config.txt"
grep -Fq '# == kaleidosphere-dsh-plugin' "$evidence_dir/happy-dump-config.txt"
run_agent happy happy "$natural_prompt"
grep -Fq 'KS_AGENT_HAPPY engine=mssql snapshot=293a896156d8f6269c4ad33e8d632da653ea180d35a4ea5f390b0be52ce3e44a' \
  "$evidence_dir/happy.out"
mv "$evidence_dir/happy.out" "$evidence_dir/happy-first.out"
mv "$evidence_dir/happy.err" "$evidence_dir/happy-first.err"
run_agent happy happy "$natural_prompt"
grep -Fq 'KS_AGENT_HAPPY engine=mssql snapshot=293a896156d8f6269c4ad33e8d632da653ea180d35a4ea5f390b0be52ce3e44a' \
  "$evidence_dir/happy.out"

install_plugin disabled
printf '%s\n' '- id: kaleidosphere-dsh-plugin' '  disabled: true' \
  >"$(home_for disabled)/profiles/headless/cordis.patch.yml"
run_agent disabled disabled "$natural_prompt"
grep -Fq 'KS_AGENT_UNAVAILABLE scenario=disabled' "$evidence_dir/disabled.out"

install_plugin malformed
run_agent malformed malformed 'Create a KaleidoSphere plan for the configured database.'
grep -Fq 'KS_AGENT_MALFORMED_REJECTED' "$evidence_dir/malformed.out"

install_plugin parameterized
for action in discovery plan preview; do
  run_agent "parameterized-$action-happy" parameterized "Run the KaleidoSphere $action workflow."
  grep -Fq "KS_AGENT_PARAMETERIZED_HAPPY $action" "$evidence_dir/parameterized-$action-happy.out"
  run_agent "parameterized-$action-invalid" parameterized "Run the malformed KaleidoSphere $action negative probe."
  grep -Fq "KS_AGENT_PARAMETERIZED_INVALID $action" "$evidence_dir/parameterized-$action-invalid.out"
  grep -Fq 'invalid arguments:' "$evidence_dir/parameterized-$action-invalid.out"
  ! grep -Fq 'EXTERNAL_BI_REQUEST_SURFACE_DENIED' "$evidence_dir/parameterized-$action-invalid.out"
done

install_plugin missing-live
printf '%s\n' '- id: kaleidosphere-dsh-plugin' '  config:' '    source:' '      mode: live' \
  >"$(home_for missing-live)/profiles/headless/cordis.patch.yml"
mkdir -p "$runtime_tmp/missing-live"
if DSH_HOME="$(home_for missing-live)" TMPDIR="$runtime_tmp/missing-live" \
  DEEPSEEK_API_KEY='local-deterministic-stub' \
  DEEPSEEK_BASE_URL="$stub_url/missing-live" \
  timeout "${DSH_AGENT_TIMEOUT_SECONDS:-90}" dsh --profile headless "$natural_prompt" \
  >"$evidence_dir/missing-live.out" 2>"$evidence_dir/missing-live.err"; then
  echo 'missing live source configuration unexpectedly booted' >&2
  exit 1
fi
grep -Fq 'KS_DSH_LIVE_PROFILE_REQUIRED' "$evidence_dir/missing-live.err"
[[ "$(find "$runtime_tmp/missing-live" -maxdepth 1 -type d -name 'kaleidosphere-dsh-*' | wc -l)" -eq 0 ]]

DSH_HOME="$(home_for happy)" dsh plugin --profile headless remove kaleidosphere-dsh-plugin \
  >"$evidence_dir/remove.log" 2>&1
DSH_HOME="$(home_for happy)" dsh --profile headless --dump-config >"$evidence_dir/removed-dump-config.txt"
! grep -Eq '# == kaleidosphere-dsh-plugin|id: kaleidosphere-dsh-plugin' "$evidence_dir/removed-dump-config.txt"
node -e 'const p=require(process.argv[1]); if(p.dependencies?.["kaleidosphere-dsh-plugin"]||p.dsh.profile.bundles.includes("kaleidosphere-dsh-plugin")) process.exit(1)' \
  "$(home_for happy)/profiles/headless/package.json"
run_agent removed happy "$natural_prompt"
grep -Fq 'KS_AGENT_UNAVAILABLE scenario=removed' "$evidence_dir/removed.out"

node --input-type=module - "$stub_log" "$evidence_dir" "$observed_sha" "$plugin_artifact_label" <<'NODE'
import fs from 'node:fs'
import path from 'node:path'

const log = fs.readFileSync(process.argv[2], 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse)
const evidenceDir = process.argv[3]
const pluginSha256 = process.argv[4]
const pluginArtifactLabel = process.argv[5]
const byScenario = name => log.filter(entry => entry.scenario === name)
const firstSteps = name => byScenario(name).filter(entry =>
  entry.toolResult === null && entry.responseKind !== 'session-title')
const toolSteps = name => byScenario(name).filter(entry => entry.toolResult !== null)
const exactTools = entry => entry.ksTools.length === 6 && new Set(entry.ksTools).size === 6
const assert = (value, message) => { if (!value) throw new Error(message) }

assert(firstSteps('no-plugin').length === 1 && firstSteps('no-plugin')[0].ksTools.length === 0,
  'no-plugin request unexpectedly exposed KaleidoSphere tools')
assert(firstSteps('disabled').length === 1 && firstSteps('disabled')[0].ksTools.length === 0,
  'disabled plugin request unexpectedly exposed KaleidoSphere tools')
assert(firstSteps('removed').length === 1 && firstSteps('removed')[0].ksTools.length === 0,
  'removed plugin request unexpectedly exposed KaleidoSphere tools')
assert(firstSteps('happy').length === 2 && firstSteps('happy').every(exactTools),
  'happy agent requests did not expose exactly six KaleidoSphere tools')
assert(toolSteps('happy').length === 2 && toolSteps('happy').every(entry => String(entry.toolResult).includes('293a8961')),
  'happy tool results did not return through the agent loop')
assert(firstSteps('malformed').length === 1 && exactTools(firstSteps('malformed')[0]),
  'malformed scenario did not advertise the six tools')
assert(toolSteps('malformed').length === 1 && String(toolSteps('malformed')[0].toolResult).includes('invalid arguments:'),
  'malformed tool arguments were not rejected by the tool layer')
for (const action of ['discovery', 'plan', 'preview']) {
  const happy = `parameterized-${action}-happy`
  const invalid = `parameterized-${action}-invalid`
  assert(firstSteps(happy).length === 1 && exactTools(firstSteps(happy)[0]), `${happy} did not expose six tools`)
  assert(firstSteps(invalid).length === 1 && exactTools(firstSteps(invalid)[0]), `${invalid} did not expose six tools`)
  const schema = firstSteps(happy)[0].ksToolSchemas.find(entry => entry.name === `kaleidosphere_${action}`)?.parameters
  assert(schema?.type === 'object' && Array.isArray(schema.required) && schema.required.length > 0,
    `${happy} did not expose an object-rooted required schema`)
  assert(Object.values(schema.properties ?? {}).every(property => !Object.hasOwn(property, 'required') && property.type !== 'json'),
    `${happy} leaked author-only schema fields`)
  assert(toolSteps(happy).length === (action === 'discovery' ? 1 : 2), `${happy} tool sequence mismatch`)
  assert(toolSteps(invalid).length === 1 && String(toolSteps(invalid)[0].toolResult).includes('invalid arguments:')
    && !String(toolSteps(invalid)[0].toolResult).includes('EXTERNAL_BI_REQUEST_SURFACE_DENIED'),
    `${invalid} did not fail at the DSH argument boundary`)
}
assert(byScenario('missing-live').length === 0,
  'missing live configuration reached the model despite load-time rejection')
assert(log.every(entry => entry.authorizationPresent), 'stub request lacked the local bearer marker')
assert(firstSteps('happy').every(entry => String(entry.userPrompt).includes('Analyze the configured KaleidoSphere database')),
  'natural-language prompt did not reach the DSH model request')

const summary = {
  schemaVersion: 'kaleidosphere.dsh/agent-e2e-probe/v1',
  evidenceClassification: {
    packageDirectToolPipeline: 'previously-proved-not-retested-by-this-summary',
    agentTurn: 'PASS_DETERMINISTIC_STUB_FORCED_TOOL_CALL',
    marketUiClick: 'NOT_TESTED_EXTERNAL_CATALOG_DEPENDENCY',
  },
  dshVersion: '0.1.0-rc.8',
  pluginArtifact: {
    label: pluginArtifactLabel,
    sha256: pluginSha256,
  },
  happy: { runs: 2, exposedTools: 6, tool: 'kaleidosphere_analyze', fixtureSnapshot: '293a896156d8f6269c4ad33e8d632da653ea180d35a4ea5f390b0be52ce3e44a' },
  negativeCases: {
    noPlugin: 'PASS',
    disabledPlugin: 'PASS',
    malformedArguments: 'PASS_DSH_INVALID_ARGS',
    parameterizedHappyNegative: 'PASS_DISCOVERY_PLAN_PREVIEW',
    missingLiveConfiguration: 'PASS_LOAD_TIME_REJECTION',
    cleanRemoval: 'PASS',
  },
  lifecycle: { oneShotRestart: 'PASS', unloadOnExit: 'PASS_ZERO_TEMP_RESIDUE', removal: 'PASS' },
  nonClaim: 'The deterministic local stub forced the tool call; this is not evidence that a real LLM semantically selected the tool.',
}
fs.writeFileSync(path.join(evidenceDir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`)
console.log(JSON.stringify(summary))
NODE
