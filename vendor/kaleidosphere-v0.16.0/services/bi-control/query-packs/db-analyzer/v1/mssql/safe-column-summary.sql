WITH bounded_scope AS (
  SELECT TOP (@maxSourceRows) {{COLUMN}} AS [value]
  FROM {{SCHEMA}}.{{RELATION}}
)
SELECT
  COUNT_BIG(1) AS [rowCount],
  COUNT_BIG(1) - COUNT_BIG([value]) AS [nullCount],
  COUNT_BIG(DISTINCT [value]) AS [distinctCount]
FROM bounded_scope;
