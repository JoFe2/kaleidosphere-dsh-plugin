WITH source_scope AS (
  SELECT {{SOURCE_COLUMN}} AS "sourceValue"
  FROM {{SOURCE_SCHEMA}}.{{SOURCE_RELATION}}
  WHERE ROWNUM <= :maxSourceRows
), target_scope AS (
  SELECT {{TARGET_COLUMN}} AS "targetValue"
  FROM {{TARGET_SCHEMA}}.{{TARGET_RELATION}}
  WHERE ROWNUM <= :maxSourceRows
)
SELECT
  (SELECT COUNT(1) FROM source_scope WHERE "sourceValue" IS NOT NULL) AS "sourceNonNullCount",
  (SELECT COUNT(DISTINCT "sourceValue") FROM source_scope) AS "sourceDistinctCount",
  (SELECT COUNT(1) FROM target_scope WHERE "targetValue" IS NOT NULL) AS "targetNonNullCount",
  (SELECT COUNT(DISTINCT "targetValue") FROM target_scope) AS "targetDistinctCount",
  (SELECT COUNT(DISTINCT source_scope."sourceValue") FROM source_scope INNER JOIN target_scope ON source_scope."sourceValue" = target_scope."targetValue") AS "matchedDistinctCount"
FROM DUAL;
