SELECT
  COUNT_BIG(1) AS [rowCount],
  COUNT_BIG(1) - COUNT_BIG({{COLUMN}}) AS [nullCount],
  COUNT_BIG(DISTINCT {{COLUMN}}) AS [distinctCount],
  CONVERT(varchar(128), MIN({{COLUMN}})) AS [minimum],
  CONVERT(varchar(128), MAX({{COLUMN}})) AS [maximum]
FROM {{SCHEMA}}.{{RELATION}};
