import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '..')
const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'))
assert.equal(manifest.version, '0.1.0-preview.5')
assert.equal(manifest.dsh.bundle.patch, './cordis.patch.yml')
assert.equal(manifest.scripts.prepare, undefined)
assert.equal(manifest.license, 'Apache-2.0')
assert.equal(manifest.peerDependencies['@deepseek-ai/dsh-tools'], '0.1.0-rc.8')

const temp = await mkdtemp(path.join(os.tmpdir(), 'ks-dsh-pack-'))
try {
  // The pack subprocess must own a private, writable npm cache under this already
  // disposable temp root: the gate must not rely on $HOME (or the repository / a
  // persistent global dir) being writable, so it stays reproducible even when HOME
  // is an empty read-only directory (PF-2). The cache is removed with `temp` in the
  // finally block.
  const packCache = path.join(temp, 'npm-cache')
  const output = execFileSync('npm', ['pack', '--json', '--pack-destination', temp, '--cache', packCache], { cwd: root, encoding: 'utf8' })
  const [packed] = JSON.parse(output)
  const paths = packed.files.map(item => item.path)
  // The pack must carry the runtime entry points, the patch, the docs, the
  // provenance manifests, and the vendor verifier; it must exclude all other
  // scripts/, all tests, and node_modules (P2A-MEDIUM-001).
  for (const required of ['package.json', 'index.js', 'cordis.patch.yml', 'CHANGELOG.md', 'COMPATIBILITY.md', 'SECURITY.md', 'LICENSE', 'NOTICE',
    'VENDORED_MANIFEST.json', 'THIRD_PARTY_MANIFEST.json', 'lib/runtime.mjs', 'scripts/verify-vendor.mjs',
    'vendor/kaleidosphere-v0.16.0/LICENSE', 'third_party/oracledb-7.0.1/LICENSE.txt']) assert(paths.includes(required), required)
  assert(!paths.some(item => item.startsWith('test/') || item.includes('node_modules')))
  assert(!paths.some(item => item.startsWith('scripts/') && item !== 'scripts/verify-vendor.mjs'),
    'the pack must include scripts/verify-vendor.mjs and no other scripts/ or test/ path')
  assert(paths.some(item => item.includes('external-api-v2.mjs')))
  assert(paths.some(item => item.includes('external-intent-evidence-bridge.mjs')))
  assert(paths.some(item => item.includes('closed-intent-conformance-pack.mjs')))
  // The packed verifier must be executable from inside the artifact: extract the
  // tarball and run scripts/verify-vendor.mjs against the packed manifests and
  // vendor trees (the script resolves its package root from its own location).
  // Any denial (nonzero exit) fails this gate closed.
  const extracted = path.join(temp, 'extracted')
  await mkdir(extracted, { recursive: true })
  execFileSync('tar', ['-xzf', path.join(temp, packed.filename), '-C', extracted], { encoding: 'utf8' })
  execFileSync(process.execPath, ['scripts/verify-vendor.mjs'], { cwd: path.join(extracted, 'package'), encoding: 'utf8' })
  process.stdout.write(`${JSON.stringify({ filename: packed.filename, size: packed.size, integrity: packed.integrity, files: paths.length })}\n`)
} finally {
  await rm(temp, { recursive: true, force: true })
}
