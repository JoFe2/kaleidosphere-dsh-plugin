import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

const scripts = [
  'scripts/test-dsh-rc8.sh',
  'scripts/test-dsh-agent-rc8.sh',
]

test('rc.8 E2E scripts use the pinned root dependency and bounded process waits', async () => {
  for (const path of scripts) {
    const source = await readFile(new URL(`../${path}`, import.meta.url), 'utf8')
    assert.doesNotMatch(source, /npm install[^\n]*@deepseek-ai\/dsh/, `${path}: dynamic DSH install`)
    assert.match(source, /tools_root="\$\{DSH_TOOLS_ROOT:-\$repo_root\}"/, `${path}: root tools pin missing`)
    assert.match(source, /wait_for_pid\(\)/, `${path}: wait helper missing`)
    assert.match(source, /timeout "\$seconds" tail --pid="\$pid" -f \/dev\/null/, `${path}: process deadline missing`)
    assert.match(source, /DSH_FILE_TIMEOUT_STEPS:-1200/, `${path}: bounded CI readiness window missing`)
  }

  const lifecycle = await readFile(new URL('../scripts/test-dsh-rc8.sh', import.meta.url), 'utf8')
  for (const marker of [
    'KS_PROBE_LOCAL_SURFACE',
    'KS_PROBE_NEGATIVE_MATRIX',
    'negative-matrix.json',
    'summary.json',
    'fixture-digests-before.json',
    'fixture-digests-after.json',
    'bounded external stub',
    'P3C-EXTERNAL-LOCAL-ONLY',
  ]) {
    assert.match(lifecycle, new RegExp(marker.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')), `lifecycle evidence marker missing: ${marker}`)
  }

  const probe = await readFile(new URL('../test/dsh-probe-bundle/index.mjs', import.meta.url), 'utf8')
  assert.match(probe, /runLocalSurfaceProbe/, 'host probe does not integrate P3A')
  assert.match(probe, /runNegativeMatrix/, 'host probe does not integrate P3B')
  assert.match(probe, /exactly six native host tools/, 'host probe tool-surface invariant missing')
  assert.match(probe, /IN_PLUGIN_PROCESS_LOCAL_RUNTIME_NOT_HOST_TOOL/, 'local-runtime authority boundary missing')
  assert.match(probe, /process\.pid/, 'probe process identity binding missing')
  assert.match(probe, /generation/, 'probe generation binding missing')
  assert.match(probe, /const records = ctx\.tools\.schemas\(\)\.map\(canonicalize\)/, 'single complete schema-record capture missing')
  assert.match(probe, /completeHostSchemaDigest/, 'complete schema-record digest evidence missing')
  assert.match(probe, /FORBIDDEN_MAPPED_EXPOSURE/, 'mapped schema exposure denylist missing')
  assert.match(probe, /if \(typeof value === 'string'\)/, 'denylist must inspect every schema-record string')
  assert.match(probe, /hostSchemaNames/, 'host schema-name evidence binding missing')
  assert.match(probe, /runLocalSurfaceProbe\([^)]*hostSchemaNames/, 'P3A host binding missing')
  assert.match(probe, /runNegativeMatrix\([^)]*hostSchemaNames/, 'P3B host binding missing')

  assert.match(lifecycle, /JSON\.parse\(fs\.readFileSync\(path\.join\(dir, 'unloaded\.json'\)/, 'unloaded evidence is not parsed')
  assert.match(lifecycle, /JSON\.parse\(fs\.readFileSync\(path\.join\(dir, 'reloaded\.json'\)/, 'reloaded evidence is not parsed')
  assert.match(lifecycle, /UNLOADED.*tools.*length.*0/s, 'unloaded state/tool assertion missing')
  assert.match(lifecycle, /RELOADED.*tools.*length.*6/s, 'reloaded exact-tool assertion missing')
  assert.match(lifecycle, /status.*response.*result.*status/s, 'reloaded status assertion missing')
  assert.match(lifecycle, /summary\.hmrUnload === 'PASS'/, 'summary must derive HMR unload PASS from assertions')
  assert.match(lifecycle, /summary\.hmrReload === 'PASS'/, 'summary must derive HMR reload PASS from assertions')
  assert.match(lifecycle, /summary\.residue === 'ZERO'/, 'summary must derive residue ZERO from assertions')
  assert.match(lifecycle, /EVIDENCE_DIR must be empty/, 'caller-supplied evidence must fail closed')
  assert.match(lifecycle, /run_id=/, 'fresh run id missing')
  assert.match(lifecycle, /assert_run_bound_json/, 'evidence run binding assertion missing')
  assert.match(lifecycle, /stale evidence preexists/, 'stale evidence rejection missing')
  assert.match(lifecycle, /runId,/, 'summary must carry the fresh run id')

  const workflow = await readFile(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8')
  assert.match(workflow, /timeout-minutes: 15/, 'CI job timeout missing')
  assert.match(workflow, /timeout 300 npm run test:dsh\b/, 'test:dsh step timeout missing')
  assert.match(workflow, /timeout 300 npm run test:dsh-agent\b/, 'test:dsh-agent step timeout missing')
})

test('F2 denies a forbidden nested mapped alias but permits prose and legitimate platform schema records', async () => {
  const { assertNoForbiddenExposure } = await import('./dsh-probe-bundle/index.mjs')
  assert.throws(() => assertNoForbiddenExposure({ metadata: { mappedAlias: 'search' } }), /forbidden mapped exposure/)
  assert.doesNotThrow(() => assertNoForbiddenExposure({ description: 'search is discussed here', platform: 'mssql' }))
  assert.doesNotThrow(() => assertNoForbiddenExposure({ name: 'kaleidosphere_status', metadata: { mappedAlias: 'platform_status' } }))
})

test('F3 rejects prefilled caller evidence instead of accepting stale files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ks-p3c-stale-'))
  await writeFile(join(dir, 'active.json'), '{"state":"ACTIVE"}\n')
  await assert.rejects(
    execFileAsync('bash', ['scripts/test-dsh-rc8.sh'], { cwd: fileURLToPath(new URL('..', import.meta.url)), env: { ...process.env, EVIDENCE_DIR: dir } }),
    error => error.code === 2 && /EVIDENCE_DIR must be empty/.test(error.stderr),
  )
})
