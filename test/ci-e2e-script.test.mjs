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

test('PF-1 every lifecycle DSH launch uses the exact flagged rc.8 launcher contract', async () => {
  const source = await readFile(new URL('../scripts/test-dsh-rc8.sh', import.meta.url), 'utf8')
  const lines = source.split('\n')
  // One exact locally pinned rc.8 CLI entry, resolved fail-closed.
  assert.match(source, /dsh_entry="\$tools_root\/node_modules\/@deepseek-ai\/dsh\/lib\/bin\.js"/, 'exact local rc.8 CLI entry pin missing')
  assert.match(source, /\[\[ -f "\$dsh_entry" \]\]/, 'CLI entry existence must fail closed')
  assert.equal(source.split('lib/bin.js').length - 1, 1, 'CLI entry must be pinned exactly once')
  // One flagged launcher contract: a simple command array carrying the
  // required --expose-internals execArgv and forwarding every argument.
  assert.match(source, /dsh_launch=\(node --expose-internals "\$dsh_entry"\)/, 'flagged launcher contract missing')
  // No bare dsh lifecycle launch may remain, flagged or not.
  const bare = lines.filter(line => /^[ \t]*(if[ \t]+)?dsh[ \t]/.test(line))
  assert.deepEqual(bare, [], `bare dsh lifecycle launches remain: ${bare.join(' | ')}`)
  // Every one of the 21 lifecycle DSH launches goes through the single launcher.
  const launches = lines.filter(line => /^(if[ \t]+)?"\$\{dsh_launch\[\@\]\}"[ \t]/.test(line))
  assert.equal(launches.length, 21, 'every lifecycle DSH launch must use the single flagged launcher')
})

test('NR-1 lifecycle owns disposable npm/pnpm/corepack state below the fresh run_root', async () => {
  const source = await readFile(new URL('../scripts/test-dsh-rc8.sh', import.meta.url), 'utf8')
  // Every package-manager writable path is derived from the fresh run_root so
  // the existing cleanup trap deletes every byte the lifecycle creates.
  for (const [name, dir] of Object.entries({
    npm_cache: 'npm-cache',
    pnpm_home: 'pnpm-home',
    xdg_cache: 'xdg-cache',
    xdg_state: 'xdg-state',
    xdg_config: 'xdg-config',
    corepack_home: 'corepack',
  })) {
    assert.match(source, new RegExp(`${name}="\\$run_root/${dir}"`), `NR-1: ${name} must be created below the fresh run_root`)
  }
  // The private writable state is pre-created, not left to fail on first write
  // when the caller HOME is empty and read-only.
  const mkdirLine = source.split('\n').find(line => line.startsWith('mkdir -p "$bin_root"'))
  for (const fragment of ['"$npm_cache"', '"$pnpm_home"', '"$xdg_cache/pnpm"', '"$xdg_state/pnpm"', '"$xdg_config/pnpm"', '"$corepack_home"']) {
    assert.ok(mkdirLine !== undefined && mkdirLine.includes(fragment), `NR-1: writable state dir ${fragment} must be pre-created below run_root`)
  }
  // Only the required subprocess env is exported, and each export routes the
  // writable state into its private run_root path.
  assert.match(source, /export npm_config_cache="\$npm_cache"/, 'NR-1: npm cache must be routed below run_root')
  assert.match(source, /export PNPM_HOME="\$pnpm_home"/, 'NR-1: pnpm home/store must be routed below run_root')
  assert.match(source, /export XDG_CACHE_HOME="\$xdg_cache"/, 'NR-1: pnpm metadata cache must be routed below run_root')
  assert.match(source, /export XDG_STATE_HOME="\$xdg_state"/, 'NR-1: pnpm state must be routed below run_root')
  assert.match(source, /export XDG_CONFIG_HOME="\$xdg_config"/, 'NR-1: pnpm config must be routed below run_root')
  assert.match(source, /export COREPACK_HOME="\$corepack_home"/, 'NR-1: corepack home must be routed below run_root')
  // No package-manager writable state may point at the caller HOME or a
  // persistent global directory.
  assert.doesNotMatch(source, /export (npm_config_cache|PNPM_HOME|XDG_[A-Z_]+HOME|COREPACK_HOME)=\$HOME/, 'NR-1: package-manager state must not be routed to caller HOME')
  // Constrained offline mode: a fail-closed pre-provisioned state root seeds
  // the private state and the lifecycle resolves dependencies offline only.
  assert.match(source, /DSH_PREPROVISIONED_STATE/, 'NR-1: pre-provisioned state root hook missing')
  assert.match(source, /\[\[ -d "\$state_root" \]\]/, 'NR-1: pre-provisioned state root must fail closed')
  assert.match(source, /cp -a "\$state_root\/pnpm\/\." "\$pnpm_home\/"/, 'NR-1: pnpm store seed must stay below run_root')
  assert.match(source, /cp -a "\$state_root\/corepack\/\." "\$corepack_home\/"/, 'NR-1: corepack home seed must stay below run_root')
  assert.match(source, /export npm_config_offline=true/, 'NR-1: constrained lifecycle must resolve dependencies offline only')
  // F1: pnpm 11.24.0 ignores npm_config_offline; the constrained lifecycle must
  // also export the exact pnpm-recognized offline configuration so an
  // incomplete pre-provisioned store cannot silently fetch from a reachable
  // registry.
  assert.match(source, /export pnpm_config_offline=true/, 'NR-1 F1: constrained lifecycle must enforce pnpm offline via the exact pnpm-recognized configuration (pnpm ignores npm_config_offline)')
  // F2: cp -a preserves the read-only source modes; the private run_root copies
  // are normalized user-writable so pnpm/corepack can write their state, while
  // the read-only source state root is never chmod'd.
  assert.match(source, /chmod -R u\+w/, 'NR-1 F2: seeded run_root copies must be normalized user-writable (cp -a preserves read-only source modes)')
  assert.match(source, /chmod -R u\+w[^\n]*"\$pnpm_home"/, 'NR-1 F2: the pnpm store copy must be made user-writable below run_root')
  assert.doesNotMatch(source, /chmod[^\n]*"\$state_root/, 'NR-1 F2: the read-only source state root must never be made writable')
})
