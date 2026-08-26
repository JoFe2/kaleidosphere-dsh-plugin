// P3B: direct executable oracle for the probe-bundle seven-class negative-matrix
// phase.
//
// Deterministic synthetic mutations drive the fixture (mssql) runtime.execute
// for the three additive v0.24.0 local actions (search/details/overview)
// through the reusable negative-matrix phase exported by this bundle; the
// oracle asserts the four P3B proof contracts:
//   P3B-MATRIX        each of the seven negative classes denies through the
//                     local runtime surface with the exact pinned code and no
//                     case succeeds,
//   P3B-CAPABILITY    the differing Search/Details/Overview pinned denial
//                     semantics are represented without inventing codes,
//   P3B-DETERMINISM   two matrix runs serialize byte-identically to the
//                     closed case set,
//   P3B-AUTHORITY     the evidence map carries no raw rows, secrets, SQL,
//                     network, executable or mutation fields.
//
// No live data, network, environment secrets, raw rows or SQL: every input is
// constructed inline by reusing the verified P3A synthetic fixture builders
// and the vendored handlers remain the single authority for every denial
// code. The rc.8 shell lifecycle (P3C) is a separate phase and out of scope
// for this oracle.

import assert from 'node:assert/strict'
import test from 'node:test'

import { canonicalJson } from '../../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/core.mjs'
import {
  P3A_FORBIDDEN_KEYS,
  P3A_FORBIDDEN_VALUE_PATTERNS,
} from './local-surface.mjs'
import { P3B_CASES, P3B_CLASSES, runNegativeMatrix } from './negative-matrix.mjs'

// Contract literals, pinned independently of the module so the oracle catches
// any drift between the matrix evidence boundary and the frozen work order.
// The seven negative classes of the work order, in closed order.
const EXPECTED_CLASSES = Object.freeze([
  'scope-drift', 'injection', 'oversized', 'stale-receipt', 'tampered-digest', 'missing-coverage', 'cancellation',
])

// The exact runtime-level denial code for every closed case, pinned from the
// P2 runtime oracles (P2B2B Search, P2B3B Details, P2B4B Overview) and the
// AbortController contract. One canonical representative case per class,
// with per-capability variants only where the exact pinned codes differ.
const EXPECTED_CASES = Object.freeze([
  Object.freeze({ id: 'P3B-SCOPE-DRIFT-SEARCH', class: 'scope-drift', action: 'search', code: 'KS_OBJECT_CAPABILITY_SCOPE_DENIED' }),
  Object.freeze({ id: 'P3B-SCOPE-DRIFT-DETAILS', class: 'scope-drift', action: 'details', code: 'KS_OBJECT_CAPABILITY_SCOPE_DENIED' }),
  Object.freeze({ id: 'P3B-SCOPE-DRIFT-OVERVIEW', class: 'scope-drift', action: 'overview', code: 'KS_OBJECT_CAPABILITY_SCOPE_DENIED' }),
  Object.freeze({ id: 'P3B-INJECTION-SEARCH', class: 'injection', action: 'search', code: 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED' }),
  Object.freeze({ id: 'P3B-INJECTION-DETAILS', class: 'injection', action: 'details', code: 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED' }),
  Object.freeze({ id: 'P3B-INJECTION-OVERVIEW-REQUEST', class: 'injection', action: 'overview', code: 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED' }),
  Object.freeze({ id: 'P3B-INJECTION-OVERVIEW-RUN', class: 'injection', action: 'overview', code: 'DB_OVERVIEW_UNSAFE_JSON' }),
  Object.freeze({ id: 'P3B-OVERSIZED-DETAILS', class: 'oversized', action: 'details', code: 'DB_OBJECT_DETAILS_EVIDENCE_INVALID' }),
  Object.freeze({ id: 'P3B-STALE-RECEIPT-DETAILS', class: 'stale-receipt', action: 'details', code: 'DB_OBJECT_DETAILS_RECEIPT_BINDING_INVALID' }),
  Object.freeze({ id: 'P3B-STALE-RECEIPT-OVERVIEW', class: 'stale-receipt', action: 'overview', code: 'KS_OBJECT_CAPABILITY_BINDING_DENIED' }),
  Object.freeze({ id: 'P3B-TAMPERED-DIGEST-SEARCH', class: 'tampered-digest', action: 'search', code: 'KS_OBJECT_SEARCH_HANDLER_PROJECTION_FORGED' }),
  Object.freeze({ id: 'P3B-TAMPERED-DIGEST-OVERVIEW', class: 'tampered-digest', action: 'overview', code: 'DB_OVERVIEW_RUN_TAMPERED' }),
  Object.freeze({ id: 'P3B-MISSING-COVERAGE-DETAILS', class: 'missing-coverage', action: 'details', code: 'DB_OBJECT_DETAILS_COVERAGE_MISSING' }),
  Object.freeze({ id: 'P3B-CANCELLATION-SEARCH', class: 'cancellation', action: 'search', code: 'AbortError' }),
  Object.freeze({ id: 'P3B-CANCELLATION-DETAILS', class: 'cancellation', action: 'details', code: 'AbortError' }),
  Object.freeze({ id: 'P3B-CANCELLATION-OVERVIEW', class: 'cancellation', action: 'overview', code: 'AbortError' }),
])

// The differing pinned denial semantics per capability (sorted for
// comparison): the shared capability-surface codes plus each capability's
// handler-level codes.
const EXPECTED_CODES_BY_ACTION = Object.freeze({
  search: Object.freeze([
    'AbortError',
    'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED',
    'KS_OBJECT_CAPABILITY_SCOPE_DENIED',
    'KS_OBJECT_SEARCH_HANDLER_PROJECTION_FORGED',
  ]),
  details: Object.freeze([
    'AbortError',
    'DB_OBJECT_DETAILS_COVERAGE_MISSING',
    'DB_OBJECT_DETAILS_EVIDENCE_INVALID',
    'DB_OBJECT_DETAILS_RECEIPT_BINDING_INVALID',
    'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED',
    'KS_OBJECT_CAPABILITY_SCOPE_DENIED',
  ]),
  overview: Object.freeze([
    'AbortError',
    'DB_OVERVIEW_RUN_TAMPERED',
    'DB_OVERVIEW_UNSAFE_JSON',
    'KS_OBJECT_CAPABILITY_BINDING_DENIED',
    'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED',
    'KS_OBJECT_CAPABILITY_SCOPE_DENIED',
  ]),
})
const ABORT_ERROR = 'AbortError'

function assertFrozen(value) {
  if (!value || typeof value !== 'object') return
  assert(Object.isFrozen(value))
  Object.values(value).forEach(assertFrozen)
}

function scanForForbiddenContent(root, label) {
  const keys = new Set()
  const strings = []
  const walk = (value) => {
    if (Array.isArray(value)) { value.forEach(walk); return }
    if (value && typeof value === 'object') {
      for (const [key, item] of Object.entries(value)) { keys.add(key); walk(item) }
      return
    }
    if (typeof value === 'string') strings.push(value)
  }
  walk(root)
  for (const key of keys) {
    assert(!P3A_FORBIDDEN_KEYS.includes(key), `${label}: forbidden key "${key}"`)
  }
  for (const value of strings) {
    for (const { name, pattern } of P3A_FORBIDDEN_VALUE_PATTERNS) {
      assert(!pattern.test(value), `${label}: ${name} content in a string value`)
    }
  }
}

// The module's evidence-boundary pins must match the frozen contract.
function assertPins() {
  assert.deepEqual(P3B_CLASSES, EXPECTED_CLASSES)
  assert.deepEqual(P3B_CASES, EXPECTED_CASES)
}

test('P3B-MATRIX: the seven negative classes each deny through the local runtime surface with the exact pinned codes and no case succeeds', async () => {
  assertPins()
  const evidence = await runNegativeMatrix()
  assert.equal(evidence.engine, 'mssql')
  assertFrozen(evidence)
  assert.deepEqual([...evidence.classes], [...EXPECTED_CLASSES])
  assert.deepEqual(evidence.cases.map(entry => entry.id), EXPECTED_CASES.map(entry => entry.id))
  for (const [index, entry] of [...evidence.cases].entries()) {
    const expected = EXPECTED_CASES[index]
    assert.equal(entry.id, expected.id)
    assert.equal(entry.class, expected.class)
    assert.equal(entry.action, expected.action)
    assert.equal(entry.code, expected.code)
    // A recorded code is a denial: a success has no code and the module
    // refuses to record one instead of reporting the matrix as green.
    assert(typeof entry.code === 'string' && entry.code.length > 0, `case ${entry.id} has no denial code`)
  }
  // Every one of the seven classes has at least one represented case.
  for (const matrixClass of EXPECTED_CLASSES) {
    assert(evidence.cases.some(entry => entry.class === matrixClass), `class ${matrixClass} is unrepresented`)
  }
})

test('P3B-CAPABILITY: the differing Search/Details/Overview pinned denial semantics are represented without inventing codes', async () => {
  const evidence = await runNegativeMatrix()
  for (const action of Object.keys(EXPECTED_CODES_BY_ACTION)) {
    const codes = evidence.cases.filter(entry => entry.action === action).map(entry => entry.code)
    assert(codes.length > 0, `action ${action} is unrepresented`)
    assert.deepEqual([...codes].sort(), [...EXPECTED_CODES_BY_ACTION[action]])
  }
  // Every observed code is a pinned KS_/DB_ fail-closed code or the platform
  // AbortError: nothing invented.
  for (const entry of evidence.cases) {
    assert(entry.code.startsWith('KS_') || entry.code.startsWith('DB_') || entry.code === ABORT_ERROR,
      `unpinned code ${entry.code} for case ${entry.id}`)
  }
})

test('P3B-DETERMINISM: two matrix runs serialize byte-identically to the closed case set', async () => {
  const first = await runNegativeMatrix()
  const second = await runNegativeMatrix()
  assert.equal(canonicalJson(first), canonicalJson(second))
  // The evidence is JSON-safe: it round-trips through JSON without loss and
  // the observed case table is exactly the closed pinned table.
  assert.deepEqual(JSON.parse(JSON.stringify(first)), first)
  assert.deepEqual(canonicalJson(first.cases), canonicalJson(EXPECTED_CASES))
})

test('P3B-AUTHORITY: the evidence map carries no raw rows, secrets, SQL, network, executable or mutation fields', async () => {
  const evidence = await runNegativeMatrix()
  // The evidence boundary is the bounded string surface: only the stable case
  // id, class, action and observed denial code.
  for (const entry of evidence.cases) {
    assert.deepEqual(Object.keys(entry).sort(), ['action', 'class', 'code', 'id'])
    for (const value of Object.values(entry)) assert(typeof value === 'string')
  }
  assert(typeof evidence.engine === 'string')
  scanForForbiddenContent(evidence, 'negative-matrix evidence')
  // Sentinel entries keep the scan non-trivial if the pins drift.
  assert(P3A_FORBIDDEN_KEYS.includes('rows'))
  assert(P3A_FORBIDDEN_KEYS.includes('password'))
  assert(P3A_FORBIDDEN_VALUE_PATTERNS.some(item => item.name === 'url-scheme'))
  assert(P3A_FORBIDDEN_VALUE_PATTERNS.some(item => item.name === 'localhost'))
})