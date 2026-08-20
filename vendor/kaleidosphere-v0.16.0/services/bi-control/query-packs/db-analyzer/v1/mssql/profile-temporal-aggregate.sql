SELECT
  COUNT_BIG(1) AS [rowCount],
  COUNT_BIG(1) - COUNT_BIG({{COLUMN}}) AS [nullCount],
  COUNT_BIG(DISTINCT {{COLUMN}}) AS [distinctCount],
  CONVERT(varchar(27), CAST(MIN({{COLUMN}}) AS datetime2(7)), 126) AS [minimum],
  CONVERT(varchar(27), CAST(MAX({{COLUMN}}) AS datetime2(7)), 126) AS [maximum],
  CONVERT(varchar(27), CAST(MAX({{COLUMN}}) AS datetime2(7)), 126) AS [freshnessMaximum]
FROM {{SCHEMA}}.{{RELATION}};
