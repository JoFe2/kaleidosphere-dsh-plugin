import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'

const packageRoot = path.resolve(import.meta.dirname, '..')
const manifest = JSON.parse(await readFile(path.join(packageRoot, 'VENDORED_MANIFEST.json'), 'utf8'))

// The exact KaleidoSphere source commit the v0.24.0 handler closure was vendored
// from (pinned by the reference manifest at SHA-256 3806d71a...dc1c7). The
// section commit and every per-file sourceCommit are compared against this exact
// value — a manifest that rewrites both jointly (e.g. to all zeros) must fail
// closed, not merely self-consistent (P2A-MEDIUM-001).
const V0240_SOURCE_COMMIT = 'e092bb0bce039936b88329793b24e9f987ae0ddb'

async function files(directory) {
  const result = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const item = path.join(directory, entry.name)
    if (entry.isDirectory()) result.push(...await files(item))
    else if (entry.isFile()) result.push(item)
  }
  return result
}

// Aggregate digest: sha256(relative-path NUL content NUL, lexicographic relative paths).
async function aggregateDigest(rootDir) {
  const digest = createHash('sha256')
  const paths = (await files(rootDir)).sort()
  for (const item of paths) {
    digest.update(`${path.relative(rootDir, item)}\0`)
    digest.update(await readFile(item))
    digest.update('\0')
  }
  return { count: paths.length, digest: digest.digest('hex') }
}

// Root 1: the pre-existing v0.16.0 runtime tree (top-level single-root schema,
// unchanged from baseline): exact file count plus aggregate digest.
{
  const vendorRoot = path.join(packageRoot, manifest.root)
  const { count, digest: computed } = await aggregateDigest(vendorRoot)
  assert.equal(count, manifest.fileCount,
    `v0.16.0 file count mismatch (manifest ${manifest.fileCount}, on disk ${count})`)
  assert.equal(computed, manifest.digest, 'v0.16.0 aggregate digest mismatch')
  process.stdout.write(`${JSON.stringify({ tag: manifest.tag, commit: manifest.commit, fileCount: count, digest: computed })}\n`)
}

// Root 2: the v0.24.0 handler closure. Fail closed on any deviation:
// every per-file SHA-256 must match its entry, the on-disk file set must equal
// the entry set exactly (no missing or extra files), every entry must carry the
// section's source commit, and the aggregate digest must match the tree.
{
  const closure = manifest.v0240
  assert.ok(closure, 'VENDORED_MANIFEST.json must carry a v0240 handler-closure section')
  assert.equal(closure.commit, V0240_SOURCE_COMMIT,
    `v0240 section commit must be the exact source commit ${V0240_SOURCE_COMMIT}`)
  const entries = closure.files
  assert.ok(Array.isArray(entries) && entries.length > 0,
    'v0240 section must carry a non-empty per-file entries array')
  assert.equal(entries.length, closure.fileCount,
    `v0240 fileCount mismatch (manifest ${closure.fileCount}, entries ${entries.length})`)

  const vendorRoot = path.join(packageRoot, closure.root)
  const onDisk = new Set((await files(vendorRoot)).map((item) => path.relative(packageRoot, item)))
  const expected = new Set(entries.map((entry) => entry.vendorPath))
  for (const entry of entries) {
    assert.equal(entry.vendorPath, `${closure.root}/${entry.sourcePath}`,
      `v0240 vendor path ${entry.vendorPath} must mirror source path ${entry.sourcePath}`)
    assert.equal(entry.sourceCommit, V0240_SOURCE_COMMIT,
      `v0240 entry ${entry.sourcePath} source commit must be the exact source commit ${V0240_SOURCE_COMMIT}`)
    const buffer = await readFile(path.join(packageRoot, entry.vendorPath), { flag: 'r' }).catch(() => null)
    assert.ok(buffer, `v0240 vendor file ${entry.vendorPath} is missing from the tree`)
    const actual = createHash('sha256').update(buffer).digest('hex')
    assert.equal(actual, entry.sha256,
      `v0240 vendor file ${entry.vendorPath} digest mismatch (manifest ${entry.sha256}, actual ${actual})`)
  }
  for (const item of onDisk) {
    assert.ok(expected.has(item), `v0240 vendor tree contains an unmanifested file ${item}`)
  }
  const { count, digest: computed } = await aggregateDigest(vendorRoot)
  assert.equal(count, entries.length,
    `v0240 on-disk file count mismatch (entries ${entries.length}, on disk ${count})`)
  assert.equal(computed, closure.digest, 'v0240 aggregate digest mismatch')
  process.stdout.write(`${JSON.stringify({ tag: closure.tag, commit: closure.commit, fileCount: count, digest: computed })}\n`)
}