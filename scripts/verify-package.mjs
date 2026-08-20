import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '..')
const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'))
assert.equal(manifest.dsh.bundle.patch, './cordis.patch.yml')
assert.equal(manifest.scripts.prepare, undefined)
assert.equal(manifest.license, 'Apache-2.0')
assert.equal(manifest.peerDependencies['@deepseek-ai/dsh-tools'], '0.1.0-rc.8')

const temp = await mkdtemp(path.join(os.tmpdir(), 'ks-dsh-pack-'))
try {
  const output = execFileSync('npm', ['pack', '--json', '--pack-destination', temp], { cwd: root, encoding: 'utf8' })
  const [packed] = JSON.parse(output)
  const paths = packed.files.map(item => item.path)
  for (const required of ['package.json', 'index.js', 'cordis.patch.yml', 'CHANGELOG.md', 'COMPATIBILITY.md', 'LICENSE', 'NOTICE',
    'VENDORED_MANIFEST.json', 'THIRD_PARTY_MANIFEST.json', 'lib/runtime.mjs',
    'vendor/kaleidosphere-v0.16.0/LICENSE', 'third_party/oracledb-7.0.1/LICENSE.txt']) assert(paths.includes(required), required)
  assert(!paths.some(item => item.startsWith('test/') || item.startsWith('scripts/') || item.includes('node_modules')))
  assert(paths.some(item => item.includes('external-api-v2.mjs')))
  assert(paths.some(item => item.includes('external-intent-evidence-bridge.mjs')))
  assert(paths.some(item => item.includes('closed-intent-conformance-pack.mjs')))
  process.stdout.write(`${JSON.stringify({ filename: packed.filename, size: packed.size, integrity: packed.integrity, files: paths.length })}\n`)
} finally {
  await rm(temp, { recursive: true, force: true })
}
