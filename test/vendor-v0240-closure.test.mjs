// Proof contract P2A: the vendored KaleidoSphere v0.24.0 handler closure must be
// byte-identical to the read-only reference (source commit e092bb0), record exact
// per-file provenance, form a closed relative-import closure plus its runtime
// filesystem dependencies, fail closed on any byte/digest tamper, and leave the
// v0.16.0 runtime tree byte-identical with the change remaining additive-only.
//
// The closure is exactly 16 files: the 15-module relative-import closure of the
// three local handlers plus one runtime filesystem dependency —
// services/bi-agent/package.json, which external-api-v2.mjs reads via
// new URL('../package.json', import.meta.url) at module load time.
//
// The per-file SHA-256 digests below are pinned from the reference manifest
// (REFERENCE-MANIFEST.json at /workspace/ks65-reference-v0240, itself pinned at
// SHA-256 3806d71a...; source commit e092bb0bce039936b88329793b24e9f987ae0ddb), so
// the test is hermetic: it proves vendor == manifest == pinned-reference digest
// without requiring the reference root. When the reference root is present in the
// environment, the test additionally proves vendor == reference byte-for-byte and
// that the reference manifest file still matches its pinned digest.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { test } from 'node:test'

const packageRoot = path.resolve(import.meta.dirname, '..')

const SOURCE_COMMIT = 'e092bb0bce039936b88329793b24e9f987ae0ddb'
const REFERENCE_MANIFEST_SHA256 = '3806d71aa99fbe6880464ce35677d88799302530fadf98f87fd5a55ad06dc1c7'
const REFERENCE_ROOT = '/workspace/ks65-reference-v0240'
const VENDOR_ROOT = 'vendor/kaleidosphere-v0.24.0'
const V016_ROOT = 'vendor/kaleidosphere-v0.16.0'
const CLOSURE_FILE_COUNT = 16

// Pinned from REFERENCE-MANIFEST.json (ks-v0240-reference/v1, source commit
// e092bb0): sourcePath -> SHA-256. Exactly 16 entries (15 modules + the
// runtime filesystem dependency services/bi-agent/package.json).
const PINNED_REFERENCE_TRIPLES = {
  'services/bi-agent/package.json': '826bcc27fa1a59514001b550a8d07c2fd129bf68089ddc98bdf626b2eb346145',
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

// The 15 module files whose relative-import closure, plus the runtime filesystem
// dependencies, must equal exactly the 16-file vendored set.
const MODULE_SOURCE_PATHS = Object.keys(PINNED_REFERENCE_TRIPLES).filter((sourcePath) => sourcePath.endsWith('.mjs'))

// The three local handler entry points of the import closure.
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
// entry, which must remain unchanged alongside the v0.24.0 origin entry.
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
const MODULE_VENDOR_PATHS = MODULE_SOURCE_PATHS.map((sourcePath) => `${VENDOR_ROOT}/${sourcePath}`)

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

// Extract relative filesystem specifiers a module resolves against
// import.meta.url (e.g. readFileSync(new URL('../package.json', import.meta.url))).
// These are runtime filesystem dependencies, not import edges: the vendor closure
// must include their targets in addition to the relative-import closure.
function relativeFilesystemSpecifiers(source) {
  const specs = new Set()
  for (const match of source.matchAll(/\bnew\s+URL\(\s*['"](\.\.?\/[^'"]+)['"]\s*,\s*import\.meta\.url/g)) {
    specs.add(match[1])
  }
  return [...specs]
}

// Run the real scripts/verify-vendor.mjs against a package root (the script
// resolves the package root from its own location) and report { status, output }.
function runRealVerifier(packageDir) {
  try {
    const stdout = execFileSync(process.execPath, [path.join(packageDir, 'scripts', 'verify-vendor.mjs')], { encoding: 'utf8' })
    return { status: 0, output: stdout }
  } catch (error) {
    return { status: typeof error.status === 'number' ? error.status : 1, output: `${error.stdout ?? ''}${error.stderr ?? ''}` }
  }
}

// Build a scratch archive that mirrors the package root the real verifier reads:
// the full v0.16.0 tree, the full v0.24.0 tree, the real verifier script, and a
// manifest copy (buffer writes, so any source file mode — the reference mount is
// read-only — cannot block mutation).
async function buildVerifierScratchArchive(scratch, manifest) {
  for (const entry of manifest.v0240.files) {
    const buffer = await readFile(path.join(packageRoot, entry.vendorPath))
    const target = path.join(scratch, entry.vendorPath)
    await mkdir(path.dirname(target), { recursive: true })
    await writeFile(target, buffer)
  }
  for (const entry of (await listFiles(path.join(packageRoot, V016_ROOT))).map((item) => path.relative(packageRoot, item))) {
    const buffer = await readFile(path.join(packageRoot, entry))
    const target = path.join(scratch, entry)
    await mkdir(path.dirname(target), { recursive: true })
    await writeFile(target, buffer)
  }
  await mkdir(path.join(scratch, 'scripts'), { recursive: true })
  await writeFile(path.join(scratch, 'scripts', 'verify-vendor.mjs'),
    await readFile(path.join(packageRoot, 'scripts', 'verify-vendor.mjs')))
  await writeFile(path.join(scratch, 'VENDORED_MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n')
}

test('P2A-P1: 16/16 vendor files byte-identical with exact per-file provenance', async () => {
  const manifest = JSON.parse(await readFile(path.join(packageRoot, 'VENDORED_MANIFEST.json'), 'utf8'))
  const closure = manifest.v0240
  assert.ok(closure, 'VENDORED_MANIFEST.json must carry a v0240 handler-closure section')
  assert.equal(closure.commit, SOURCE_COMMIT, 'v0240 section must pin source commit e092bb0')
  assert.equal(closure.root, VENDOR_ROOT, 'v0240 section must pin the distinct side-by-side vendor root')
  assert.equal(closure.fileCount, CLOSURE_FILE_COUNT, 'v0240 section must record exactly 16 files')
  assert.equal(closure.referenceManifestSha256, REFERENCE_MANIFEST_SHA256,
    'v0240 section must pin the reference manifest digest')

  const entries = closure.files
  assert.ok(Array.isArray(entries), 'v0240 section must carry a per-file entries array')
  assert.equal(entries.length, CLOSURE_FILE_COUNT, 'exactly 16 per-file entries, no missing or extra')

  const seenSourcePaths = new Set()
  const seenVendorPaths = new Set()
  for (const entry of entries) {
    assert.equal(entry.sourceCommit, SOURCE_COMMIT, `source commit must be e092bb0 for ${entry.sourcePath}`)
    assert.ok(PINNED_REFERENCE_TRIPLES[entry.sourcePath] !== undefined,
      `source path ${entry.sourcePath} must be one of the 16 pinned reference paths`)
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
  assert.equal(seenSourcePaths.size, CLOSURE_FILE_COUNT, 'all 16 pinned source paths present exactly once')

  // The closure aggregate digest must match the on-disk tree (same algorithm as
  // the verify:package gates), so the recorded digest cannot drift from reality.
  const aggregate = await aggregateDigest(path.join(packageRoot, VENDOR_ROOT))
  assert.equal(aggregate.count, CLOSURE_FILE_COUNT, 'vendor root must contain exactly the 16 vendored files')
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

test('P2A-P2: the 16-file set is exactly the import closure of the three handlers plus runtime filesystem dependencies', async () => {
  // (1) Every relative import in every vendored module resolves inside the vendor set.
  const adjacency = new Map()
  for (const vendorPath of MODULE_VENDOR_PATHS) {
    const file = path.join(packageRoot, vendorPath)
    const source = await readFile(file, 'utf8')
    const targets = new Set()
    for (const spec of relativeImportSpecifiers(source)) {
      const resolved = path.resolve(path.dirname(file), spec)
      const resolvedVendor = path.relative(packageRoot, resolved)
      assert.ok(VENDOR_PATHS.includes(resolvedVendor),
        `relative import ${spec} in ${vendorPath} must resolve inside the 16-file vendor set (got ${resolvedVendor})`)
      targets.add(resolvedVendor)
    }
    adjacency.set(vendorPath, [...targets])
  }

  // (2) BFS from the three handler entry points reaches exactly the 15 module files.
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
  assert.equal(visited.size, MODULE_SOURCE_PATHS.length,
    'BFS from the three handlers must reach exactly the 15 vendored module files')
  for (const vendorPath of MODULE_VENDOR_PATHS) {
    assert.ok(visited.has(vendorPath), `${vendorPath} must be reachable from the handler entry points`)
  }

  // (3) Runtime filesystem dependencies (new URL('<rel>', import.meta.url) reads)
  // must resolve inside the vendor set; the closure pins exactly one.
  const filesystemDeps = new Set()
  for (const vendorPath of VENDOR_PATHS) {
    const file = path.join(packageRoot, vendorPath)
    const source = await readFile(file, 'utf8')
    for (const spec of relativeFilesystemSpecifiers(source)) {
      const resolved = path.relative(packageRoot, path.resolve(path.dirname(file), spec))
      assert.ok(VENDOR_PATHS.includes(resolved),
        `runtime filesystem dependency ${spec} in ${vendorPath} must resolve inside the vendor set (got ${resolved})`)
      filesystemDeps.add(resolved)
    }
  }
  assert.deepEqual([...filesystemDeps].sort(),
    [`${VENDOR_ROOT}/services/bi-agent/package.json`],
    'the closure must have exactly one runtime filesystem dependency: services/bi-agent/package.json')

  // (4) The 16-file vendor set is exactly import closure ∪ filesystem dependencies:
  // no file in the set is unreachable, and nothing outside the set is imported.
  const expected = new Set([...visited, ...filesystemDeps])
  assert.equal(expected.size, CLOSURE_FILE_COUNT, 'import closure plus filesystem dependencies must total 16 files')
  assert.deepEqual([...expected].sort(), [...VENDOR_PATHS].sort(),
    'the vendored set must equal the closed import closure plus its runtime filesystem dependencies')
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

test('P2A-P3b: the real verifier fails closed — manifest digest mutation and byte flip both exit nonzero', async () => {
  // Persistent negative test against scripts/verify-vendor.mjs itself (not a test-
  // local reimplementation): a per-file manifest digest mutation and a vendor file
  // byte flip in a scratch archive must each make the real verifier exit nonzero,
  // while the unmutated scratch archive passes.
  const manifest = JSON.parse(await readFile(path.join(packageRoot, 'VENDORED_MANIFEST.json'), 'utf8'))
  const entries = manifest.v0240.files
  const scratch = await mkdtemp(path.join(os.tmpdir(), 'ks-v0240-verifier-'))
  try {
    // Build a scratch archive: full vendor tree, real verifier script, manifest copy.
    await buildVerifierScratchArchive(scratch, manifest)

    // Clean scratch archive: the real verifier must pass (exit 0).
    const clean = runRealVerifier(scratch)
    assert.equal(clean.status, 0, `unmutated scratch archive must pass the real verifier (got exit ${clean.status}: ${clean.output})`)

    // (a) Per-file manifest digest mutation: flip the last hex char of
    // v0240.files[0].sha256 in the scratch manifest. The real verifier must exit
    // nonzero (P2A-MEDIUM-001: previously it exited 0).
    const mutatedManifest = JSON.parse(await readFile(path.join(scratch, 'VENDORED_MANIFEST.json'), 'utf8'))
    const digest = mutatedManifest.v0240.files[0].sha256
    mutatedManifest.v0240.files[0].sha256 = `${digest.slice(0, -1)}${digest.slice(-1) === 'a' ? 'b' : 'a'}`
    await writeFile(path.join(scratch, 'VENDORED_MANIFEST.json'), JSON.stringify(mutatedManifest, null, 2) + '\n')
    const digestMutated = runRealVerifier(scratch)
    assert.notEqual(digestMutated.status, 0,
      'per-file manifest digest mutation must make the real verifier exit nonzero')

    // Restore the clean manifest copy, then flip one byte of one vendored file.
    await writeFile(path.join(scratch, 'VENDORED_MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n')
    const victim = path.join(scratch, entries[0].vendorPath)
    const bytes = await readFile(victim)
    bytes[0] = bytes[0] ^ 0x01
    await writeFile(victim, bytes)
    const byteFlipped = runRealVerifier(scratch)
    assert.notEqual(byteFlipped.status, 0,
      'a byte-flipped vendor file must make the real verifier exit nonzero')

    // (b) A missing vendor file must also be denied by the real verifier.
    await writeFile(victim, await readFile(path.join(packageRoot, entries[0].vendorPath)))
    await rm(path.join(scratch, entries[1].vendorPath), { force: true })
    const fileMissing = runRealVerifier(scratch)
    assert.notEqual(fileMissing.status, 0,
      'a missing vendor file must make the real verifier exit nonzero')
  } finally {
    await rm(scratch, { recursive: true, force: true })
  }

  // The real tree must still pass the real verifier and be unaltered.
  const real = runRealVerifier(packageRoot)
  assert.equal(real.status, 0, `real tree must pass the real verifier (got exit ${real.status}: ${real.output})`)
})

test('P2A-P3c: joint commit mutation — v0240.commit and every sourceCommit zeroed are denied by the real verifier', async () => {
  // P2A-MEDIUM-001: the verifier compared each sourceCommit only to the section
  // commit, so zeroing both jointly (with digests intact) exited 0. It must
  // compare closure.commit and every per-file sourceCommit to the exact source
  // commit e092bb0b..., which denies the joint mutation and each single-field
  // variant.
  const manifest = JSON.parse(await readFile(path.join(packageRoot, 'VENDORED_MANIFEST.json'), 'utf8'))
  const scratch = await mkdtemp(path.join(os.tmpdir(), 'ks-v0240-joint-'))
  const writeManifest = (doc) => writeFile(path.join(scratch, 'VENDORED_MANIFEST.json'), JSON.stringify(doc, null, 2) + '\n')
  try {
    await buildVerifierScratchArchive(scratch, manifest)

    const clean = runRealVerifier(scratch)
    assert.equal(clean.status, 0, `unmutated scratch archive must pass the real verifier (got exit ${clean.status}: ${clean.output})`)

    // (a) JOINT MUTATION: zero the section commit AND every per-file sourceCommit.
    const joint = JSON.parse(await readFile(path.join(scratch, 'VENDORED_MANIFEST.json'), 'utf8'))
    joint.v0240.commit = '0'.repeat(40)
    for (const entry of joint.v0240.files) entry.sourceCommit = '0'.repeat(40)
    await writeManifest(joint)
    const jointResult = runRealVerifier(scratch)
    assert.notEqual(jointResult.status, 0,
      'joint commit mutation must make the real verifier exit nonzero (P2A-MEDIUM-001)')

    // (b) Zeroing the section commit alone must also be denied: the verifier must
    // compare closure.commit to the exact source commit, not to the entries.
    await writeManifest(manifest)
    const sectionOnly = JSON.parse(await readFile(path.join(scratch, 'VENDORED_MANIFEST.json'), 'utf8'))
    sectionOnly.v0240.commit = '0'.repeat(40)
    await writeManifest(sectionOnly)
    const sectionOnlyResult = runRealVerifier(scratch)
    assert.notEqual(sectionOnlyResult.status, 0,
      'a zeroed v0240.commit alone must make the real verifier exit nonzero')

    // (c) Zeroing every per-file sourceCommit alone must also be denied.
    await writeManifest(manifest)
    const entriesOnly = JSON.parse(await readFile(path.join(scratch, 'VENDORED_MANIFEST.json'), 'utf8'))
    for (const entry of entriesOnly.v0240.files) entry.sourceCommit = '0'.repeat(40)
    await writeManifest(entriesOnly)
    const entriesOnlyResult = runRealVerifier(scratch)
    assert.notEqual(entriesOnlyResult.status, 0,
      'zeroed per-file sourceCommits alone must make the real verifier exit nonzero')
  } finally {
    await rm(scratch, { recursive: true, force: true })
  }

  // The real tree must still pass the real verifier and be unaltered.
  const real = runRealVerifier(packageRoot)
  assert.equal(real.status, 0, `real tree must pass the real verifier (got exit ${real.status}: ${real.output})`)
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
  assert.equal(v0240.fileCount, CLOSURE_FILE_COUNT, 'v0.24.0 entry must scope exactly 16 files')
  assert.deepEqual([...(v0240.files ?? [])].sort(),
    Object.keys(PINNED_REFERENCE_TRIPLES).sort(),
    'v0.24.0 file scope must match the 16 vendored paths exactly')

  // The recorded aggregate digest must match a fresh recomputation (same algorithm
  // as scripts/verify-third-party.mjs, which the verify:package gate runs).
  const aggregate = await aggregateDigest(path.join(packageRoot, VENDOR_ROOT))
  assert.equal(aggregate.digest, v0240.digest, 'v0.24.0 recorded digest must match the on-disk tree')
})

test('P2A-P6: the three handlers are executable import probes — the closure loads and exports its capability bindings', async () => {
  // Executable proof of the runtime filesystem dependency: external-api-v2.mjs
  // reads ../package.json at module load time, so all three handler entry points
  // fail to import unless services/bi-agent/package.json is vendored.
  const overview = await import(pathToFileURL(path.join(packageRoot, `${VENDOR_ROOT}/services/bi-agent/src/database-overview-handler-v1.mjs`)).href)
  assert.equal(overview.DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID, 'bi.database.overview.read')
  assert.equal(typeof overview.handleDatabaseOverviewRequestV1, 'function')

  const details = await import(pathToFileURL(path.join(packageRoot, `${VENDOR_ROOT}/services/bi-agent/src/object-details-handler-v1.mjs`)).href)
  assert.equal(details.KS_OBJECT_DETAILS_HANDLER_CAPABILITY, 'bi.object.details.read')
  assert.equal(typeof details.handleObjectDetailsV1, 'function')

  const search = await import(pathToFileURL(path.join(packageRoot, `${VENDOR_ROOT}/services/bi-agent/src/object-search-handler-v1.mjs`)).href)
  assert.equal(search.KS_OBJECT_SEARCH_HANDLER_CAPABILITY_ID, 'bi.object.search.read')
  assert.equal(typeof search.handleObjectSearchV1, 'function')
})