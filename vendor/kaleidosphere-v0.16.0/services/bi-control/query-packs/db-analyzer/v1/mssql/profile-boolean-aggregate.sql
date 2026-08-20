SELECT
  COUNT_BIG(1) AS [rowCount],
  COUNT_BIG(1) - COUNT_BIG({{COLUMN}}) AS [nullCount],
  COUNT_BIG(DISTINCT {{COLUMN}}) AS [distinctCount]
FROM {{SCHEMA}}.{{RELATION}};
