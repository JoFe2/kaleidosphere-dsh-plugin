SELECT
  c.owner AS schema_name,
  c.table_name AS relation_name,
  c.constraint_name,
  CASE c.constraint_type
    WHEN 'P' THEN 'PRIMARY_KEY'
    WHEN 'U' THEN 'UNIQUE'
    WHEN 'R' THEN 'FOREIGN_KEY'
    WHEN 'C' THEN 'CHECK'
  END AS constraint_kind,
  cc.column_name,
  cc.position AS ordinal_position,
  rc.owner AS referenced_schema_name,
  rc.table_name AS referenced_relation_name,
  rcc.column_name AS referenced_column_name,
  CASE c.constraint_type WHEN 'C' THEN c.search_condition_vc END AS check_expression,
  CASE c.constraint_type WHEN 'R' THEN c.delete_rule END AS delete_rule,
  CAST(NULL AS VARCHAR2(60)) AS update_rule,
  CASE c.status WHEN 'ENABLED' THEN 1 ELSE 0 END AS is_enabled,
  CASE c.validated WHEN 'VALIDATED' THEN 1 ELSE 0 END AS is_validated,
  CASE c.deferrable WHEN 'DEFERRABLE' THEN 1 ELSE 0 END AS is_deferrable,
  CASE c.deferred WHEN 'DEFERRED' THEN 1 ELSE 0 END AS is_initially_deferred
FROM all_constraints c
LEFT JOIN all_cons_columns cc
  ON cc.owner = c.owner
  AND cc.constraint_name = c.constraint_name
  AND cc.table_name = c.table_name
LEFT JOIN all_constraints rc
  ON rc.owner = c.r_owner
  AND rc.constraint_name = c.r_constraint_name
LEFT JOIN all_cons_columns rcc
  ON rcc.owner = rc.owner
  AND rcc.constraint_name = rc.constraint_name
  AND rcc.table_name = rc.table_name
  AND rcc.position = cc.position
WHERE c.constraint_type IN ('P', 'U', 'R', 'C')
ORDER BY c.owner, c.table_name, constraint_kind, c.constraint_name, cc.position, cc.column_name;
