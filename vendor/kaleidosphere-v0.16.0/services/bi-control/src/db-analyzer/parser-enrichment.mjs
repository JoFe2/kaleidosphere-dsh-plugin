import { identitySha256, normalizeJsonValue } from './core.mjs';

export const PARSER_ENRICHMENT_INPUT_SCHEMA = 'chimpmaera.db/parser-enrichment-input/v1';
export const PARSER_ENRICHMENT_EVIDENCE_SCHEMA = 'chimpmaera.db/parser-enrichment-evidence/v1';
export const PARSER_DIALECT_CONTRACT = 'COMMON-SELECT-SUBSET/V1';

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};

const hasExactKeys = (value, expected) => value
  && typeof value === 'object'
  && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());

const validName = (value) => typeof value === 'string'
  && value.length > 0
  && value.length <= 128
  && value === value.normalize('NFC')
  && !/[\u0000-\u001f\u007f]/.test(value);

const objectKey = (value) => `${value.sourceSchemaName}\u0000${value.sourceObjectName}\u0000${value.sourceObjectKind}`;
const dynamicSql = /\b(?:sp_executesql|EXEC(?:UTE)?\s*\(|EXECUTE\s+IMMEDIATE)\b/i;

const parserMetadata = (lock) => {
  if (!hasExactKeys(lock, ['packageName', 'version', 'spdx', 'integrity', 'sourceUrl', 'dialectContract'])
    || lock.packageName !== 'node-sql-parser'
    || lock.version !== '5.4.0'
    || lock.spdx !== 'Apache-2.0'
    || !/^sha512-[A-Za-z0-9+/]+=*$/.test(lock.integrity ?? '')
    || lock.sourceUrl !== 'https://github.com/taozhi8833998/node-sql-parser'
    || lock.dialectContract !== PARSER_DIALECT_CONTRACT) fail('DB_PARSER_PROVENANCE_INVALID');
  return normalizeJsonValue({
    ...lock,
    requiredForNativeCollector: false,
    promotionPolicy: 'NEVER_PROVEN',
  });
};

const finalize = ({ state, parser, parsedObjectCount, edges, gaps }) => {
  edges.sort((left, right) => left.edgeSha256.localeCompare(right.edgeSha256));
  gaps.sort((left, right) => left.gapSha256.localeCompare(right.gapSha256));
  const body = normalizeJsonValue({
    schemaVersion: PARSER_ENRICHMENT_EVIDENCE_SCHEMA,
    state,
    optional: true,
    parser,
    summary: {
      parsedObjectCount,
      inferredEdgeCount: edges.length,
      blindSpotGapCount: gaps.length,
      rawDefinitionsIncluded: false,
    },
    edges,
    gaps,
  });
  return { ...body, enrichmentSha256: identitySha256(body) };
};

export async function buildOptionalParserEnrichment({
  storedLogicEvidence,
  sourceFixture,
  parserLock,
  loadParser = () => import('node-sql-parser'),
}) {
  const parser = parserMetadata(parserLock);
  if (!hasExactKeys(sourceFixture, ['schemaVersion', 'engine', 'objects'])
    || sourceFixture.schemaVersion !== PARSER_ENRICHMENT_INPUT_SCHEMA
    || sourceFixture.engine !== storedLogicEvidence.engine
    || !Array.isArray(sourceFixture.objects)
    || sourceFixture.objects.length > 32) fail('DB_PARSER_INPUT_INVALID');

  let Parser;
  try {
    const loaded = await loadParser();
    Parser = loaded?.Parser ?? loaded?.default?.Parser;
  } catch {
    return finalize({ state: 'UNAVAILABLE', parser, parsedObjectCount: 0, edges: [], gaps: [] });
  }
  if (typeof Parser !== 'function') {
    return finalize({ state: 'UNAVAILABLE', parser, parsedObjectCount: 0, edges: [], gaps: [] });
  }

  const knownObjects = new Map(storedLogicEvidence.objects.map((object) => [objectKey({
    sourceSchemaName: object.schemaName,
    sourceObjectName: object.objectName,
    sourceObjectKind: object.objectKind,
  }), object]));
  const seen = new Set();
  const edges = [];
  const gaps = [];
  let parsedObjectCount = 0;
  const parserContractSha256 = identitySha256(parser);
  const instance = new Parser();

  for (const entry of sourceFixture.objects) {
    if (!hasExactKeys(entry, ['sourceSchemaName', 'sourceObjectName', 'sourceObjectKind', 'sourceText'])
      || !validName(entry.sourceSchemaName) || !validName(entry.sourceObjectName)
      || !['PROCEDURE', 'FUNCTION', 'TRIGGER'].includes(entry.sourceObjectKind)
      || typeof entry.sourceText !== 'string' || entry.sourceText.length === 0 || entry.sourceText.length > 4096) {
      fail('DB_PARSER_INPUT_INVALID');
    }
    const key = objectKey(entry);
    const sourceObject = knownObjects.get(key);
    if (!sourceObject || sourceObject.definitionVisibility !== 'VISIBLE_HASHED' || seen.has(key)) {
      fail('DB_PARSER_SOURCE_INVALID');
    }
    seen.add(key);
    const sourceTextSha256 = identitySha256(entry.sourceText);
    const common = normalizeJsonValue({
      sourceObjectIdentitySha256: sourceObject.objectIdentitySha256,
      sourceSchemaName: entry.sourceSchemaName,
      sourceObjectName: entry.sourceObjectName,
      sourceObjectKind: entry.sourceObjectKind,
      sourceTextSha256,
      parserContractSha256,
    });
    const recordGap = (gapState) => {
      const gap = normalizeJsonValue({ ...common, gapState });
      gaps.push({ ...gap, gapSha256: identitySha256(gap) });
    };
    if (dynamicSql.test(entry.sourceText)) {
      recordGap('DYNAMIC_SQL_BLIND_SPOT');
      continue;
    }
    if (!/^\s*SELECT\b/i.test(entry.sourceText)
      || entry.sourceText.split(';').filter((part) => part.trim().length > 0).length !== 1) {
      recordGap('UNSUPPORTED_SYNTAX_BLIND_SPOT');
      continue;
    }
    let tableList;
    try {
      tableList = instance.tableList(entry.sourceText, { database: 'MySQL' });
    } catch {
      recordGap('UNSUPPORTED_SYNTAX_BLIND_SPOT');
      continue;
    }
    if (!Array.isArray(tableList) || tableList.length === 0) {
      recordGap('UNSUPPORTED_SYNTAX_BLIND_SPOT');
      continue;
    }
    parsedObjectCount += 1;
    for (const reference of [...new Set(tableList)]) {
      const [action, targetSchemaName, targetObjectName, extra] = reference.split('::');
      if (action !== 'select' || extra !== undefined || !validName(targetSchemaName) || !validName(targetObjectName)) {
        fail('DB_PARSER_OUTPUT_INVALID');
      }
      const edge = normalizeJsonValue({
        ...common,
        targetSchemaName,
        targetObjectName,
        targetObjectKind: 'RELATION_UNKNOWN',
        proofState: 'INFERRED_PARSER',
      });
      edges.push({ ...edge, edgeSha256: identitySha256(edge) });
    }
  }
  if (new Set(edges.map(({ edgeSha256 }) => edgeSha256)).size !== edges.length
    || new Set(gaps.map(({ gapSha256 }) => gapSha256)).size !== gaps.length) fail('DB_PARSER_OUTPUT_INVALID');
  return finalize({
    state: gaps.length === 0 ? 'SUCCEEDED' : 'PARTIAL',
    parser,
    parsedObjectCount,
    edges,
    gaps,
  });
}
