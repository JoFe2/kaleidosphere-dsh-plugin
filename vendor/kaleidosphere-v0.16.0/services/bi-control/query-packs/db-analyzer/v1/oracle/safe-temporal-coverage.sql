WITH bounded_scope AS (
  SELECT {{COLUMN}} AS "value"
  FROM {{SCHEMA}}.{{RELATION}}
  WHERE ROWNUM <= :maxSourceRows
)
SELECT
  COUNT(1) AS "rowCount",
  COUNT(1) - COUNT("value") AS "nullCount",
  COUNT(DISTINCT "value") AS "distinctCount",
  TO_CHAR(MIN("value"), 'YYYY-MM-DD"T"HH24:MI:SS.FF6') AS "minimum",
  TO_CHAR(MAX("value"), 'YYYY-MM-DD"T"HH24:MI:SS.FF6') AS "maximum",
  TO_CHAR(MAX("value"), 'YYYY-MM-DD"T"HH24:MI:SS.FF6') AS "freshnessMaximum"
FROM bounded_scope;
