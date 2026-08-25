// Proof contract P2A: the vendored KaleidoSphere v0.24.0 handler closure must be
// byte-identical to the read-only reference (source commit e092bb0), record exact
// per-file provenance, form a closed relative-import closure, fail closed on any
// byte/digest tamper, and leave the v0.16.0 runtime tree byte-identical with the
// change remaining additive-only.
//
// The per-file SHA-256 digests below are pinned from the reference manifest
// (REFERENCE-MANIFEST.json at /workspace/ks65-reference-v0240, itself pinned at
// SHA-256 2b82ed4e...; source commit e092bb0bce039936b88329793b24e9f987ae0ddb), so
// the test is hermetic: it proves vendor == manifest == pinned-reference digest
// without requiring the reference root. When the reference root is present in the
// environment, the test additionally proves vendor == reference byte-for-byte and
// that the reference manifest file still matches its pinned digest.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'

const packageRoot = path.resolve(import.meta.dirname, '..')

const SOURCE_COMMIT = 'e092bb0bce039936b88329793b24e9f987ae0ddb'
const REFERENCE_MANIFEST_SHA256 = '2b82ed4ebcfa03b5470fb9583ea98dda991890a6dc6b98b3de2ee4d1455bdd2b'
const REFERENCE_ROOT = '/workspace/ks65-reference-v0240'
const VENDOR_ROOT = 'vendor/kaleidosphere-v0.24.0'
const V016_ROOT = 'vendor/kaleidosphere-v0.16.0'

// Pinned from REFERENCE-MANIFEST.json (ks-v0240-reference/v1, source commit
// e092bb0): sourcePath -> SHA-256. Exactly 15 entries.
const PINNED_REFERENCE_TRIPLES = {
  'services/bi-agent/src/database-overview-handler-v1.mjs': 'e015f9e408b676bdba7f55740b504bb364c66744c3f24e5a60aa938e4ca8f8a1',
  'services/bi-agent/src/external-api-v2.mjs': 'b11f7162317a38392e41fbf5feda5dd49435fd2248dead2d2276d84a100e3076',
  'services/bi-agent/src/object-capability-contract-v1.mjs': 'c68e6aefef42362e1aadaeb0ae23614db38b33b2ef9991b1847be03963efae72',
  'services/bi-agent/src/object-details-handler-v1.mjs': 'abd5c5256737c8771c50ed7138be5fec4ed92b9fb791f46da6aaba2ec2fd8b79',
  'services/bi-agent/src/object-search-handler-v1.mjs': '94e7ba13ca85cc10a407900e0049a9fa86e8dccfb6de8d26f90e50af5b492b37',
  'services/bi-control/src/db-analyzer/core.mjs': '12f331b0e4589fc0a192bec2cc90718c8c266557218f80cb5f3748e15c7ffbb3',
  'services/bi-control/src/db-analyzer/database-overview-projection-v1.mjs': '9ba648295190b7ae1b366010ff404cf41a3b0cd5d55e315f520482ee53d6d270',
  'services/bi-control/src/db-analyzer/object-details-projection-v1.mjs': 'e09d31c274e80ae21cb41c5934f484cfd25b2dc88acbd22115d0ecb1ce5b91fd',
  'services/bi-control/src/db-analyzer/object-inventory-authority-digest-v1.mjs': 'ae586d113ca686d7955ba40f3447755bf084e7e110f51fbbf08a7fd456cccce7',
  'services/bi-control/src/db-analyzer/object-name-authority-v1.mjs': '455aeb181dabf52b4bdab0c12b5635c786a9f141430d3ee23d6e1a7139022f39',
  'services/bi-control/src/db-analyzer/object-relation-kind-authority-v1.mjs': '93fa9f3ed4fb0bb30781ad9e6717429e45f9ea8453af5e74f8d87f72c52f173e',
  'services/bi-control/src/db-analyzer/object-search-authority-bound-result-v1.mjs': '4e0b9ead811fda94e9e97d0a758bf3b9335f351283b7df9d72e8bfcf1e9298a0',
  'services/bi-control/src/db-analyzer/object-search-envelope-v1.mjs': 'cebd170a87c1937abfc12f34b6997629b808a8b0df30f04e88f6520c156ee69c',
  'services/bi-control/src/db-analyzer/progressive-controller.mjs': 'be3555e25334ad5506a7bd8f2324e6b84dd2a6c1effd820abd1fd9067b428235',
  'services/bi-control/src/db-analyzer/safe-analysis-methods.mjs': 'b77f0b0347cf6d80a8c8b0e10cac51244c9ad96bc653f3c983f792bdf7647b1a'
}

// The three local handler entry points whose relative-import closure must equal
// exactly the 15-file vendored set.
const HANDLER_ENTRIES = [
  'services/bi-agent/src/database-overview-handler-v1.mjs',
  'services/bi-agent/src/object-details-handler-v1.mjs',
  'services/bi-agent/src/object-search-handler-v1.mjs'
]

// Baseline (origin/main 414b40b) of the pre-existing v0.16.0 provenance record in
// VENDORED_MANIFEST.json. These keys must remain byte-identical after the change
// (scripts/verify-vendor.mjs depends on the top-level single-root schema).
const BASELINE_V016_PROVENANCE = {
  schemaVersion: 'kaleidosphere.dsh/vendored-runtime-provenance/v1',
  upstream: 'https://github.com/JoFe2/KaleidoSphere',
  tag: 'v0.16.0',
  commit: '5a73ff8146afa0067d226cffa639efde959e8fde',
  license: 'Apache-2.0',
  root: V016_ROOT,
  fileCount: 73,
  digestAlgorithm: 'sha256(relative-path NUL content NUL, lexicographic paths)',
  digest: 'f62109b120c0bc677d47ce4ce8e23278a30bacd7bc3555c1f4877d09cefd58a2'
}

// Baseline (origin/main 414b40b) of the pre-existing THIRD_PARTY_MANIFEST.json
// entry, which must remain unchanged alongside the new v0.24.0 origin entry.
const BASELINE_ORACLEDB_ENTRY = {
  name: 'oracledb',
  version: '7.0.1',
  source: 'https://www.npmjs.com/package/oracledb/v/7.0.1',
  license: 'Apache-2.0 OR UPL-1.0',
  selectedLicense: 'Apache-2.0',
  root: 'third_party/oracledb-7.0.1',
  fileCount: 136,
  digestAlgorithm: 'sha256(relative-path NUL content NUL, lexicographic paths)',
  digest: '04418f36c746a5f1c3ccf2b67288bfd99f1260765cbb0e5d937f189973426c43'
}

const VENDOR_PATHS = Object.keys(PINNED_REFERENCE_TRIPLES).map((sourcePath) => `${VENDOR_ROOT}/${sourcePath}`)

const sha256Hex = (buffer) => createHash('sha256').update(buffer).digest('hex')

// Aggregate digest over a vendor root, identical algorithm to
// scripts/verify-vendor.mjs / scripts/verify-third-party.mjs:
// sha256(relative-path NUL content NUL, lexicographic relative paths).
async function aggregateDigest(rootDir) {
  const digest = createHash('sha256')
  const paths = (await listFiles(rootDir)).sort()
  for (const item of paths) {
    digest.update(`${path.relative(rootDir, item)}\0`)
    digest.update(await readFile(item))
    digest.update('\0')
  }
  return { count: paths.length, digest: digest.digest('hex') }
}

async function listFiles(directory) {
  const result = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const item = path.join(directory, entry.name)
    if (entry.isDirectory()) result.push(...await listFiles(item))
    else if (entry.isFile()) result.push(item)
  }
  return result
}

// Fail-closed digest verification of a manifest entry set against a tree on disk.
// Any missing file or digest mismatch denies (ok === false); an empty entry set
// also denies.
async function verifyVendoredClosure({ baseDir, entries }) {
  const result = { ok: false, missing: [], mismatches: [] }
  if (!Array.isArray(entries) || entries.length === 0) return result
  let rootSeen = false
  for (const entry of entries) {
    const file = path.join(baseDir, entry.vendorPath)
    let buffer
    try {
      buffer = await readFile(file)
    } catch {
      result.missing.push(entry.vendorPath)
      continue
    }
    rootSeen = true
    const actual = sha256Hex(buffer)
    if (actual !== entry.sha256) {
      result.mismatches.push({ vendorPath: entry.vendorPath, expected: entry.sha256, actual })
    }
  }
  result.ok = rootSeen && result.missing.length === 0 && result.mismatches.length === 0
  return result
}

// Extract relative import specifiers ('./x' or '../x') from an ES module source:
// static `from` clauses, bare side-effect imports, and dynamic import() calls.
function relativeImportSpecifiers(source) {
  const specs = new Set()
  const patterns = [
    /\bfrom\s+['"]([^'"]+)['"]/g,
    /\bimport\s*\(?\s*['"]([^'"]+)['"]/g
  ]
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const spec = match[1]
      if (spec.startsWith('./') || spec.startsWith('../')) specs.add(spec)
    }
  }
  return [...specs]
}

test('P2A-P1: 15/15 vendor files byte-identical with exact per-file provenance', async () => {
  const manifest = JSON.parse(await readFile(path.join(packageRoot, 'VENDORED_MANIFEST.json'), 'utf8'))
  const closure = manifest.v0240
  assert.ok(closure, 'VENDORED_MANIFEST.json must carry a v0240 handler-closure section')
  assert.equal(closure.commit, SOURCE_COMMIT, 'v0240 section must pin source commit e092bb0')
  assert.equal(closure.root, VENDOR_ROOT, 'v0240 section must pin the distinct side-by-side vendor root')
  assert.equal(closure.fileCount, 15, 'v0240 section must record exactly 15 files')
  assert.equal(closure.referenceManifestSha256, REFERENCE_MANIFEST_SHA256,
    'v0240 section must pin the reference manifest digest')

  const entries = closure.files
  assert.ok(Array.isArray(entries), 'v0240 section must carry a per-file entries array')
  assert.equal(entries.length, 15, 'exactly 15 per-file entries, no missing or extra')

  const seenSourcePaths = new Set()
  const seenVendorPaths = new Set()
  for (const entry of entries) {
    assert.equal(entry.sourceCommit, SOURCE_COMMIT, `source commit must be e092bb0 for ${entry.sourcePath}`)
    assert.ok(PINNED_REFERENCE_TRIPLES[entry.sourcePath] !== undefined,
      `source path ${entry.sourcePath} must be one of the 15 pinned reference paths`)
    assert.equal(seenSourcePaths.has(entry.sourcePath), false, `duplicate source path ${entry.sourcePath}`)
    seenSourcePaths.add(entry.sourcePath)
    assert.equal(entry.vendorPath, `${VENDOR_ROOT}/${entry.sourcePath}`,
      `vendor path must mirror the source path under ${VENDOR_ROOT}`)
    assert.equal(seenVendorPaths.has(entry.vendorPath), false, `duplicate vendor path ${entry.vendorPath}`)
    seenVendorPaths.add(entry.vendorPath)

    const buffer = await readFile(path.join(packageRoot, entry.vendorPath))
    const actual = sha256Hex(buffer)
    assert.equal(actual, PINNED_REFERENCE_TRIPLES[entry.sourcePath],
      `vendor file ${entry.vendorPath} must be byte-identical to the e092bb0 reference (pinned digest)`)
    assert.equal(entry.sha256, PINNED_REFERENCE_TRIPLES[entry.sourcePath],
      `manifest entry digest for ${entry.vendorPath} must equal the pinned reference digest`)
  }
  assert.equal(seenSourcePaths.size, 15, 'all 15 pinned source paths present exactly once')

  // The closure aggregate digest must match the on-disk tree (same algorithm as
  // the verify:package gates), so the recorded digest cannot drift from reality.
  const aggregate = await aggregateDigest(path.join(packageRoot, VENDOR_ROOT))
  assert.equal(aggregate.count, 15, 'vendor root must contain exactly the 15 vendored files')
  assert.equal(aggregate.digest, closure.digest, 'recorded aggregate digest must match the on-disk tree')
})

test('P2A-P1b: vendor tree pairwise byte-identical to the reference root (when present)', async (t) => {
  let referenceExists = true
  try {
    await stat(REFERENCE_ROOT)
  } catch {
    referenceExists = false
  }
  if (!referenceExists) {
    t.skip('reference root /workspace/ks65-reference-v0240 absent; hermetic pinning still holds')
    return
  }

  const referenceManifest = await readFile(path.join(REFERENCE_ROOT, 'REFERENCE-MANIFEST.json'))
  assert.equal(sha256Hex(referenceManifest), REFERENCE_MANIFEST_SHA256,
    'reference manifest file must still match its pinned SHA-256')
  const pinned = JSON.parse(referenceManifest.toString('utf8'))
  assert.equal(pinned.source_commit, SOURCE_COMMIT)
  assert.deepEqual(Object.fromEntries(Object.entries(pinned.files).sort()), PINNED_REFERENCE_TRIPLES,
    'pinned in-repo triples must equal the reference manifest file triples')

  for (const [sourcePath, digest] of Object.entries(PINNED_REFERENCE_TRIPLES)) {
    const referenceBuffer = await readFile(path.join(REFERENCE_ROOT, sourcePath))
    const vendorBuffer = await readFile(path.join(packageRoot, VENDOR_ROOT, sourcePath))
    assert.equal(sha256Hex(referenceBuffer), digest, `reference file ${sourcePath} digest drift`)
    assert.deepEqual([...vendorBuffer], [...referenceBuffer],
      `vendor file ${sourcePath} must equal reference byte-for-byte`)
  }
})

test('P2A-P2: the 15-file set is exactly the closed relative-import closure of the three handlers', async () => {
  const adjacency = new Map()
  for (const vendorPath of VENDOR_PATHS) {
    const file = path.join(packageRoot, vendorPath)
    const source = await readFile(file, 'utf8')
    const targets = new Set()
    for (const spec of relativeImportSpecifiers(source)) {
      const resolved = path.resolve(path.dirname(file), spec)
      const resolvedVendor = path.relative(packageRoot, resolved)
      assert.ok(VENDOR_PATHS.includes(resolvedVendor),
        `relative import ${spec} in ${vendorPath} must resolve inside the 15-file vendor set (got ${resolvedVendor})`)
      targets.add(resolvedVendor)
    }
    adjacency.set(vendorPath, [...targets])
  }

  const visited = new Set()
  const queue = HANDLER_ENTRIES.map((sourcePath) => `${VENDOR_ROOT}/${sourcePath}`)
  while (queue.length > 0) {
    const current = queue.pop()
    if (visited.has(current)) continue
    visited.add(current)
    for (const target of adjacency.get(current) ?? []) {
      if (!visited.has(target)) queue.push(target)
    }
  }
  assert.equal(visited.size, 15, 'BFS from the three handlers must reach exactly the 15 vendored files')
  for (const vendorPath of VENDOR_PATHS) {
    assert.ok(visited.has(vendorPath), `${vendorPath} must be reachable from the handler entry points`)
  }
})

test('P2A-P3: tamper denial — byte flip and digest corruption are both denied, real tree stays clean', async () => {
  const entries = JSON.parse(await readFile(path.join(packageRoot, 'VENDORED_MANIFEST.json'), 'utf8')).v0240.files
  const scratch = await mkdtemp(path.join(os.tmpdir(), 'ks-v0240-tamper-'))
  try {
    // Mirror the vendor tree into a scratch copy (buffer writes, so any source
    // file mode — the reference mount is read-only — cannot block mutation).
    for (const entry of entries) {
      const buffer = await readFile(path.join(packageRoot, entry.vendorPath))
      const target = path.join(scratch, entry.vendorPath)
      await mkdir(path.dirname(target), { recursive: true })
      await writeFile(target, buffer)
    }

    const clean = await verifyVendoredClosure({ baseDir: scratch, entries })
    assert.equal(clean.ok, true, 'unmutated scratch copy must verify clean')

    // (a) Flip one byte of one vendored file in the scratch copy: verification must deny.
    const victim = path.join(scratch, entries[0].vendorPath)
    const bytes = await readFile(victim)
    bytes[0] = bytes[0] ^ 0x01
    await writeFile(victim, bytes)
    const byteFlipped = await verifyVendoredClosure({ baseDir: scratch, entries })
    assert.equal(byteFlipped.ok, false, 'byte-flipped file must be denied')
    assert.equal(byteFlipped.mismatches.length, 1, 'exactly one mismatch must be reported')
    assert.equal(byteFlipped.mismatches[0].vendorPath, entries[0].vendorPath)

    // Restore the scratch file, then corrupt one manifest digest entry instead.
    await writeFile(victim, await readFile(path.join(packageRoot, entries[0].vendorPath)))

    // (b) Corrupt one digest entry in a manifest copy: verification must deny.
    const corruptedEntries = entries.map((entry, index) => {
      if (index !== 0) return entry
      const last = entry.sha256.slice(-1)
      const flipped = last === 'a' ? 'b' : 'a'
      return { ...entry, sha256: `${entry.sha256.slice(0, -1)}${flipped}` }
    })
    const digestCorrupted = await verifyVendoredClosure({ baseDir: scratch, entries: corruptedEntries })
    assert.equal(digestCorrupted.ok, false, 'corrupted digest entry must be denied')
    assert.equal(digestCorrupted.mismatches.length, 1, 'exactly one mismatch must be reported')

    // (c) Missing file also denies: drop one file from the scratch tree and verify
    // against the full expected entry set.
    const absent = path.join(scratch, entries[1].vendorPath)
    await rm(absent, { force: true })
    const missing = await verifyVendoredClosure({ baseDir: scratch, entries })
    assert.equal(missing.ok, false, 'a missing vendor file must be denied')
    assert.deepEqual(missing.missing, [entries[1].vendorPath], 'the absent file must be reported missing')

    // The real tree must still verify clean and be unaltered.
    const real = await verifyVendoredClosure({ baseDir: packageRoot, entries })
    assert.equal(real.ok, true, 'real vendor tree must verify clean after tamper tests')
    for (const entry of entries) {
      const buffer = await readFile(path.join(packageRoot, entry.vendorPath))
      assert.equal(sha256Hex(buffer), entry.sha256, `real tree file ${entry.vendorPath} must be unaltered`)
    }
  } finally {
    await rm(scratch, { recursive: true, force: true })
  }
})

test('P2A-P4: v0.16.0 runtime tree byte-identical to baseline and pre-existing provenance preserved', async () => {
  const manifest = JSON.parse(await readFile(path.join(packageRoot, 'VENDORED_MANIFEST.json'), 'utf8'))
  for (const [key, value] of Object.entries(BASELINE_V016_PROVENANCE)) {
    assert.deepEqual(manifest[key], value, `pre-existing v0.16.0 provenance key ${key} must be unchanged`)
  }

  // Hash-compare the entire v0.16.0 tree against the baseline pinned aggregate
  // digest (file count + content digest), identical algorithm to verify-vendor.mjs.
  const aggregate = await aggregateDigest(path.join(packageRoot, V016_ROOT))
  assert.equal(aggregate.count, BASELINE_V016_PROVENANCE.fileCount, 'v0.16.0 file count must be unchanged')
  assert.equal(aggregate.digest, BASELINE_V016_PROVENANCE.digest, 'v0.16.0 tree must be byte-identical to baseline')

  // The vendor root must contain exactly the two side-by-side version roots.
  const roots = (await readdir(path.join(packageRoot, 'vendor'), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
  assert.deepEqual(roots, ['kaleidosphere-v0.16.0', 'kaleidosphere-v0.24.0'],
    'vendor root must hold exactly the v0.16.0 and v0.24.0 roots side-by-side')
})

test('P2A-P5: THIRD_PARTY_MANIFEST records the v0.24.0 origin alongside the unchanged oracledb entry', async () => {
  const manifest = JSON.parse(await readFile(path.join(packageRoot, 'THIRD_PARTY_MANIFEST.json'), 'utf8'))
  assert.equal(manifest.schemaVersion, 'kaleidosphere.dsh/third-party-provenance/v1')
  assert.ok(Array.isArray(manifest.packages))

  const oracledb = manifest.packages.find((entry) => entry.name === 'oracledb')
  assert.deepEqual(oracledb, BASELINE_ORACLEDB_ENTRY, 'pre-existing oracledb entry must be byte-identical to baseline')

  const v0240 = manifest.packages.find((entry) => entry.root === VENDOR_ROOT)
  assert.ok(v0240, 'a v0.24.0 origin entry with the vendored root must exist')
  assert.equal(v0240.version, '0.24.0')
  assert.ok(v0240.commit === SOURCE_COMMIT || v0240.commit.startsWith('e092bb0'),
    'v0.24.0 entry must pin source commit e092bb0')
  assert.equal(v0240.fileCount, 15, 'v0.24.0 entry must scope exactly 15 files')
  assert.deepEqual([...(v0240.files ?? [])].sort(),
    Object.keys(PINNED_REFERENCE_TRIPLES).sort(),
    'v0.24.0 file scope must match the 15 vendored paths exactly')

  // The recorded aggregate digest must match a fresh recomputation (same algorithm
  // as scripts/verify-third-party.mjs, which the verify:package gate runs).
  const aggregate = await aggregateDigest(path.join(packageRoot, VENDOR_ROOT))
  assert.equal(aggregate.digest, v0240.digest, 'v0.24.0 recorded digest must match the on-disk tree')
})