// Release-version contract: the immutable prerelease identity for the v0.1.0-
// preview.5 increment (the merged #65 change set) must be exactly 0.1.0-
// preview.5 in BOTH the package manifest and the lockfile. A stale identity
// (e.g. the previous 0.1.0-preview.4) is denied fail-closed, so a release
// commit cannot ship the wrong identity, and the lockfile cannot drift from
// the manifest.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '..')

test('release-version contract: package.json and package-lock.json identities are exactly 0.1.0-preview.5', async () => {
  const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'))
  const lock = JSON.parse(await readFile(path.join(root, 'package-lock.json'), 'utf8'))
  assert.equal(manifest.name, 'kaleidosphere-dsh-plugin')
  assert.equal(manifest.version, '0.1.0-preview.5')
  assert.equal(lock.name, 'kaleidosphere-dsh-plugin')
  assert.equal(lock.version, '0.1.0-preview.5')
  assert.equal(lock.packages[''].version, '0.1.0-preview.5')
})