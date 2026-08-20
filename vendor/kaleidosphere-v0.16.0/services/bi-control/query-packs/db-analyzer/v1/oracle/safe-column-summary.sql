WITH bounded_scope AS (
  SELECT {{COLUMN}} AS "value"
  FROM {{SCHEMA}}.{{RELATION}}
  WHERE ROWNUM <= :maxSourceRows
)
SELECT
  COUNT(1) AS "rowCount",
  COUNT(1) - COUNT("value") AS "nullCount",
  COUNT(DISTINCT "value") AS "distinctCount"
FROM bounded_scope;
