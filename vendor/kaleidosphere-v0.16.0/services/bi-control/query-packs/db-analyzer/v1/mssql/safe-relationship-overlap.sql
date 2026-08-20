WITH source_scope AS (
  SELECT TOP (@maxSourceRows) {{SOURCE_COLUMN}} AS [sourceValue]
  FROM {{SOURCE_SCHEMA}}.{{SOURCE_RELATION}}
), target_scope AS (
  SELECT TOP (@maxSourceRows) {{TARGET_COLUMN}} AS [targetValue]
  FROM {{TARGET_SCHEMA}}.{{TARGET_RELATION}}
)
SELECT
  (SELECT COUNT_BIG(1) FROM source_scope WHERE [sourceValue] IS NOT NULL) AS [sourceNonNullCount],
  (SELECT COUNT_BIG(DISTINCT [sourceValue]) FROM source_scope) AS [sourceDistinctCount],
  (SELECT COUNT_BIG(1) FROM target_scope WHERE [targetValue] IS NOT NULL) AS [targetNonNullCount],
  (SELECT COUNT_BIG(DISTINCT [targetValue]) FROM target_scope) AS [targetDistinctCount],
  (SELECT COUNT_BIG(DISTINCT source_scope.[sourceValue]) FROM source_scope INNER JOIN target_scope ON source_scope.[sourceValue] = target_scope.[targetValue]) AS [matchedDistinctCount];
