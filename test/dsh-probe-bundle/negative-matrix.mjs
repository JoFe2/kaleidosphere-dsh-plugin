// P3B: the probe-bundle seven-negative matrix phase.
//
// Deterministic synthetic mutations drive the fixture (mssql) runtime.execute
// for the three additive v0.24.0 local actions (search/details/overview) so
// that each of the seven frozen negative classes denies fail-closed with its
// exact pinned code; the phase captures the observed denial codes in a sealed,
// read-only, evidence-bound map for the P3B oracle
// (negative-matrix.test.mjs):
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
// Everything is synthetic: representative inputs are re-issued per run from
// the verified P3A fixture builders (local-surface.mjs), every case dispatches
// through runtime.execute (never the vendored handlers directly), the vendored
// handlers remain the single authority for every denial code, and no live
// data, network, environment secrets, raw rows or SQL is touched. A case that
// resolves is a hard failure, not evidence: the matrix is green only when every
// case denies with its pinned code. The rc.8 shell lifecycle (P3C) is a
// separate phase and out of scope here.

import { KaleidoSphereRuntime } from '../../lib/runtime.mjs'
import { identitySha256 } from '../../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/core.mjs'
import {
  DETAILS_STATES,
  deepFreezeValue,
  detailsLedgerFor,
  detailsLedgerWithEntry,
  detailsProjectionInputFor,
  detailsRawEntry,
  detailsReceiptFor,
  syntheticDetailsScenario,
  syntheticOverviewScenario,
  syntheticSearchFixture,
  validSearchHandlerInput,
} from './local-surface.mjs'

// The fixture source mode resolves to the mssql engine; the matrix pins that
// single engine so every observed denial code is reproducible.
const ENGINE = 'mssql'

// The seven negative classes of the frozen work order, in closed order.
export const P3B_CLASSES = Object.freeze([
  'scope-drift', 'injection', 'oversized', 'stale-receipt', 'tampered-digest', 'missing-coverage', 'cancellation',
])

// The exact pinned denial code for every closed case, observed through the P2
// runtime oracles (P2B2B Search, P2B3B Details, P2B4B Overview), the search
// handler's projection-forge check and the AbortController contract. The run
// cross-checks every observed code against this table: a drift is a hard
// failure, never silently recorded evidence.
const P3B_PINNED_CODES = Object.freeze({
  'P3B-SCOPE-DRIFT-SEARCH': 'KS_OBJECT_CAPABILITY_SCOPE_DENIED',
  'P3B-SCOPE-DRIFT-DETAILS': 'KS_OBJECT_CAPABILITY_SCOPE_DENIED',
  'P3B-SCOPE-DRIFT-OVERVIEW': 'KS_OBJECT_CAPABILITY_SCOPE_DENIED',
  'P3B-INJECTION-SEARCH': 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED',
  'P3B-INJECTION-DETAILS': 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED',
  'P3B-INJECTION-OVERVIEW-REQUEST': 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED',
  'P3B-INJECTION-OVERVIEW-RUN': 'DB_OVERVIEW_UNSAFE_JSON',
  'P3B-OVERSIZED-DETAILS': 'DB_OBJECT_DETAILS_EVIDENCE_INVALID',
  'P3B-STALE-RECEIPT-DETAILS': 'DB_OBJECT_DETAILS_RECEIPT_BINDING_INVALID',
  'P3B-STALE-RECEIPT-OVERVIEW': 'KS_OBJECT_CAPABILITY_BINDING_DENIED',
  'P3B-TAMPERED-DIGEST-SEARCH': 'KS_OBJECT_SEARCH_HANDLER_PROJECTION_FORGED',
  'P3B-TAMPERED-DIGEST-OVERVIEW': 'DB_OVERVIEW_RUN_TAMPERED',
  'P3B-MISSING-COVERAGE-DETAILS': 'DB_OBJECT_DETAILS_COVERAGE_MISSING',
  'P3B-CANCELLATION-SEARCH': 'AbortError',
  'P3B-CANCELLATION-DETAILS': 'AbortError',
  'P3B-CANCELLATION-OVERVIEW': 'AbortError',
})

// A pre-aborted AbortSignal: runtime.execute throws the platform AbortError
// before any action dispatch.
function abortedSignal() {
  const controller = new AbortController()
  controller.abort()
  return controller.signal
}

// The stable code of a denial: the fail-closed code string when present,
// otherwise the platform error name (AbortError). A denial without either is
// a hard failure: an uncodeable denial cannot be pinned evidence.
const codeOf = (error) => {
  const code = typeof error?.code === 'string' && error.code.length > 0 ? error.code : error?.name
  if (typeof code !== 'string' || code.length === 0) {
    throw new Error('negative-matrix: the denial carried no stable code')
  }
  return code
}

// The representative local-action inputs and their synthetic support values,
// re-issued once per matrix run from the verified P3A fixture builders: a
// first-page search, a COMPLETE details projection and an overview run
// carrying a cancelled receipt.
function matrixValues() {
  const { sources, envelope } = syntheticSearchFixture(ENGINE)
  const search = validSearchHandlerInput({ engine: ENGINE, sources, envelope })
  const details = syntheticDetailsScenario(ENGINE, DETAILS_STATES.COMPLETE)
  const overview = syntheticOverviewScenario(ENGINE, { withCancelledReceipt: true })
  return {
    search,
    details,
    overview: { request: overview.request, run: deepFreezeValue(overview.run) },
  }
}

// The closed case set: one canonical representative case per class, with
// per-capability variants only where the exact pinned codes differ. Every
// build returns fresh input objects so the shared representative values stay
// unmutated, and every input is dispatched through runtime.execute.
const P3B_CASE_SPECS = [
  // Scope drift / substitution: the request scope no longer matches the
  // authoritative scope of the capability bindings.
  {
    id: 'P3B-SCOPE-DRIFT-SEARCH',
    class: 'scope-drift',
    action: 'search',
    build: ({ search }) => ({ input: { ...search, request: { ...search.request, scope: { schemas: ['other'] } } } }),
  },
  {
    id: 'P3B-SCOPE-DRIFT-DETAILS',
    class: 'scope-drift',
    action: 'details',
    build: ({ details }) => ({ input: { request: { ...details.request, scope: { schemas: ['other'] } }, projectionInput: details.projectionInput } }),
  },
  {
    id: 'P3B-SCOPE-DRIFT-OVERVIEW',
    class: 'scope-drift',
    action: 'overview',
    build: ({ overview }) => ({ input: { ...overview, request: { ...overview.request, scope: { schemas: ['other'] } } } }),
  },
  // Injection / forged input: an unsafe key on the capability request
  // surface, plus an unsafe key planted in the Overview run payload.
  {
    id: 'P3B-INJECTION-SEARCH',
    class: 'injection',
    action: 'search',
    build: ({ search }) => ({ input: { ...search, request: { ...search.request, sql: 'SELECT 1' } } }),
  },
  {
    id: 'P3B-INJECTION-DETAILS',
    class: 'injection',
    action: 'details',
    build: ({ details }) => ({ input: { request: { ...details.request, sql: 'SELECT 1' }, projectionInput: details.projectionInput } }),
  },
  {
    id: 'P3B-INJECTION-OVERVIEW-REQUEST',
    class: 'injection',
    action: 'overview',
    build: ({ overview }) => ({ input: { ...overview, request: { ...overview.request, sql: 'SELECT 1' } } }),
  },
  {
    id: 'P3B-INJECTION-OVERVIEW-RUN',
    class: 'injection',
    action: 'overview',
    build: ({ overview }) => ({ input: { ...overview, run: deepFreezeValue({ ...overview.run, sql: 'SELECT 1' }) } }),
  },
  // Oversized evidence input: an evidence reference list above the pinned
  // Details evidence bound.
  {
    id: 'P3B-OVERSIZED-DETAILS',
    class: 'oversized',
    action: 'details',
    build: ({ details }) => {
      const oversized = detailsRawEntry({ engine: ENGINE })
      oversized.evidenceRefs = Array.from({ length: 17 }, (_, index) => identitySha256({ kind: 'oversized-evidence', index }))
      return { input: { request: details.request, projectionInput: detailsProjectionInputFor(ENGINE, { entry: oversized, ledger: detailsLedgerWithEntry(details.ledger, oversized) }) } }
    },
  },
  // Stale receipt / binding: a receipt sealed over an unrelated coverage
  // entry, and an Overview request whose bindings derive from a different run.
  {
    id: 'P3B-STALE-RECEIPT-DETAILS',
    class: 'stale-receipt',
    action: 'details',
    build: ({ details }) => {
      const unrelated = detailsLedgerFor(ENGINE, DETAILS_STATES.COMPLETE, { relationName: 'other_orders' })
      return { input: { request: details.request, projectionInput: detailsProjectionInputFor(ENGINE, { entry: details.entry, ledger: details.ledger, receipt: detailsReceiptFor(ENGINE, { entry: unrelated.entry, ledger: unrelated.ledger }) }) } }
    },
  },
  {
    id: 'P3B-STALE-RECEIPT-OVERVIEW',
    class: 'stale-receipt',
    action: 'overview',
    build: ({ overview }) => ({ input: { ...overview, request: syntheticOverviewScenario(ENGINE, { withCancelledReceipt: false }).request } }),
  },
  // Tampered digest / envelope / run: a zeroed projection digest and a run
  // whose body no longer matches its pinned state seal.
  {
    id: 'P3B-TAMPERED-DIGEST-SEARCH',
    class: 'tampered-digest',
    action: 'search',
    build: ({ search }) => ({ input: { ...search, projection: { ...search.projection, projectionSha256: '0'.repeat(64) } } }),
  },
  {
    id: 'P3B-TAMPERED-DIGEST-OVERVIEW',
    class: 'tampered-digest',
    action: 'overview',
    build: ({ overview }) => ({ input: { ...overview, run: deepFreezeValue({ ...overview.run, scope: { ...overview.run.scope, schemas: ['other'] } }) } }),
  },
  // Missing coverage: an object key with no coverage entry in the ledger.
  {
    id: 'P3B-MISSING-COVERAGE-DETAILS',
    class: 'missing-coverage',
    action: 'details',
    build: ({ details }) => ({ input: { request: details.request, projectionInput: { ...details.projectionInput, objectKey: identitySha256({ kind: 'missing-object' }) } } }),
  },
  // Cancellation: a pre-aborted AbortSignal for every capability.
  {
    id: 'P3B-CANCELLATION-SEARCH',
    class: 'cancellation',
    action: 'search',
    build: ({ search }) => ({ input: search, signal: abortedSignal() }),
  },
  {
    id: 'P3B-CANCELLATION-DETAILS',
    class: 'cancellation',
    action: 'details',
    build: ({ details }) => ({ input: { request: details.request, projectionInput: details.projectionInput }, signal: abortedSignal() }),
  },
  {
    id: 'P3B-CANCELLATION-OVERVIEW',
    class: 'cancellation',
    action: 'overview',
    build: ({ overview }) => ({ input: overview, signal: abortedSignal() }),
  },
]

// The closed case set as the evidence-boundary pins: the stable case id,
// class, action and the exact pinned denial code for every case.
export const P3B_CASES = Object.freeze(
  P3B_CASE_SPECS.map((spec) => Object.freeze({ id: spec.id, class: spec.class, action: spec.action, code: P3B_PINNED_CODES[spec.id] })),
)

/**
 * Run the P3B seven-negative matrix: dispatch every closed case through the
 * fixture runtime.execute, require a fail-closed denial carrying the exact
 * pinned code for each, and return one sealed, JSON-safe, read-only evidence
 * bundle of `{ engine, classes, cases }`. A resolved case or an uncodeable or
 * drifted denial is a hard failure. The runtime is always disposed.
 * @returns {Promise<object>} The frozen P3B evidence bundle:
 *   `{ engine, classes, cases }` where each case entry is
 *   `{ id, class, action, code }`.
 */
export async function runNegativeMatrix() {
  const values = matrixValues()
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    const cases = []
    for (const spec of P3B_CASE_SPECS) {
      const { input, signal } = spec.build(values)
      let denied
      let succeeded = false
      try {
        await runtime.execute(spec.action, input, signal)
        succeeded = true
      } catch (error) {
        denied = error
      }
      if (succeeded) {
        throw new Error(`negative-matrix case ${spec.id} succeeded; every case must deny fail-closed`)
      }
      const code = codeOf(denied)
      const pinned = P3B_PINNED_CODES[spec.id]
      if (code !== pinned) {
        throw new Error(`negative-matrix case ${spec.id}: observed code ${code} drifted from pinned code ${pinned}`)
      }
      cases.push(deepFreezeValue({ id: spec.id, class: spec.class, action: spec.action, code }))
    }
    return Object.freeze({ engine: ENGINE, classes: P3B_CLASSES, cases: Object.freeze(cases) })
  } finally {
    await runtime.dispose()
  }
}