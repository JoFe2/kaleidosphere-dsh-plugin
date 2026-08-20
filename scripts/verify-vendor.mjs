import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'

const packageRoot = path.resolve(import.meta.dirname, '..')
const manifest = JSON.parse(await readFile(path.join(packageRoot, 'VENDORED_MANIFEST.json'), 'utf8'))
const vendorRoot = path.join(packageRoot, manifest.root)

async function files(directory) {
  const result = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const item = path.join(directory, entry.name)
    if (entry.isDirectory()) result.push(...await files(item))
    else if (entry.isFile()) result.push(item)
  }
  return result
}

const paths = (await files(vendorRoot)).sort()
const digest = createHash('sha256')
for (const item of paths) {
  digest.update(`${path.relative(vendorRoot, item)}\0`)
  digest.update(await readFile(item))
  digest.update('\0')
}

assert.equal(paths.length, manifest.fileCount)
assert.equal(digest.digest('hex'), manifest.digest)
process.stdout.write(`${JSON.stringify({ tag: manifest.tag, commit: manifest.commit, fileCount: paths.length, digest: manifest.digest })}\n`)
