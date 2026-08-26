// Proof contract PF-2: the package-verification gate must be self-contained and
// reproducible when HOME is an empty read-only directory. The verifier's internal
// `npm pack` subprocess must own a private writable cache under its already
// disposable temp root, so the gate never needs to write its npm cache into $HOME,
// the repository, or any persistent global directory.
//
// The focused test below executes the REAL `npm run verify:package` command under
// an empty read-only HOME, with any inherited npm cache overrides stripped from the
// environment. Before the production change this run fails at `npm pack` (ENOENT/
// EACCES on `$HOME/.npm`); after it, the run succeeds, the constrained HOME is
// found untouched (empty), and the existing pack/extract/verify-vendor assertions
// still run unchanged inside the command.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { chmod, mkdir, mkdtemp, readdir, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'

const packageRoot = path.resolve(import.meta.dirname, '..')

// Environment variables that override the npm cache location. The test strips these
// so an ambient writable cache can never silently rescue the run: the only viable
// cache under the constrained HOME is the verifier's own private one.
const NPM_CACHE_OVERRIDE_VARS = [
  'npm_config_cache',
  'npm_config_cache_localprefix',
  'npm_cache',
]

// Run the real package-verification command with a supplied environment and report
// { status, output }. A nonzero exit is captured (not thrown) so the test can assert
// on the failure and its cause.
function runVerifyPackage(env) {
  try {
    const stdout = execFileSync('npm', ['run', 'verify:package'], { cwd: packageRoot, env, encoding: 'utf8' })
    return { status: 0, output: stdout }
  } catch (error) {
    return { status: typeof error.status === 'number' ? error.status : 1, output: `${error.stdout ?? ''}${error.stderr ?? ''}` }
  }
}

test('PF-2: npm run verify:package succeeds under an empty read-only HOME (self-owned pack cache)', async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'ks-pf2-home-'))
  const home = path.join(temp, 'home')
  try {
    // Empty read-only HOME: any attempt by npm to write its cache into $HOME
    // (mkdir `$HOME/.npm`) must fail, so success here proves the verifier owns its
    // pack cache elsewhere.
    await mkdir(home)
    await chmod(home, 0o555)

    // Inherit the ambient environment but constrain HOME and remove every inherited
    // npm cache override.
    const env = { ...process.env, HOME: home }
    for (const key of NPM_CACHE_OVERRIDE_VARS) delete env[key]

    const result = runVerifyPackage(env)
    assert.equal(result.status, 0,
      `npm run verify:package must succeed under an empty read-only HOME (got exit ${result.status}):\n${result.output}`)

    // The constrained HOME must remain empty: the private pack cache must not have
    // been written into $HOME (nor the repository / a persistent global dir).
    const homeEntries = await readdir(home)
    assert.deepEqual(homeEntries, [],
      'the empty read-only HOME must remain empty: the pack cache must not be written into $HOME')
  } finally {
    // Restore write permission so the temp root can be removed, then clean up the
    // disposable root (the verifier cleans its own pack cache inside its own temp
    // root via its existing finally block).
    await chmod(home, 0o755).catch(() => {})
    await rm(temp, { recursive: true, force: true })
  }
})