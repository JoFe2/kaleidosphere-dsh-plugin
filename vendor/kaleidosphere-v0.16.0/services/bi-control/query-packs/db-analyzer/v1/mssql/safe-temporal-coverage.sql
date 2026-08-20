WITH bounded_scope AS (
  SELECT TOP (@maxSourceRows) {{COLUMN}} AS [value]
  FROM {{SCHEMA}}.{{RELATION}}
)
SELECT
  COUNT_BIG(1) AS [rowCount],
  COUNT_BIG(1) - COUNT_BIG([value]) AS [nullCount],
  COUNT_BIG(DISTINCT [value]) AS [distinctCount],
  CONVERT(varchar(33), CAST(MIN([value]) AS datetime2(7)), 126) AS [minimum],
  CONVERT(varchar(33), CAST(MAX([value]) AS datetime2(7)), 126) AS [maximum],
  CONVERT(varchar(33), CAST(MAX([value]) AS datetime2(7)), 126) AS [freshnessMaximum]
FROM bounded_scope;
