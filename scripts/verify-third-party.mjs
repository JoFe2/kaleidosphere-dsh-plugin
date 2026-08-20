import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'

const packageRoot = path.resolve(import.meta.dirname, '..')
const manifest = JSON.parse(await readFile(path.join(packageRoot, 'THIRD_PARTY_MANIFEST.json'), 'utf8'))

async function files(directory) {
  const result = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const item = path.join(directory, entry.name)
    if (entry.isDirectory()) result.push(...await files(item))
    else if (entry.isFile()) result.push(item)
  }
  return result
}

for (const entry of manifest.packages) {
  const root = path.join(packageRoot, entry.root)
  const paths = (await files(root)).sort()
  const digest = createHash('sha256')
  for (const item of paths) {
    digest.update(`${path.relative(root, item)}\0`)
    digest.update(await readFile(item))
    digest.update('\0')
  }
  assert.equal(paths.length, entry.fileCount)
  assert.equal(digest.digest('hex'), entry.digest)
  process.stdout.write(`${JSON.stringify({ name: entry.name, version: entry.version, fileCount: paths.length, digest: entry.digest })}\n`)
}
