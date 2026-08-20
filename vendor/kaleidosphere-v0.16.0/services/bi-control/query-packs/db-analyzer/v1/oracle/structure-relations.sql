SELECT
  owner AS schema_name,
  object_name AS relation_name,
  object_type AS relation_kind,
  object_id,
  TO_CHAR(created, 'YYYY-MM-DD"T"HH24:MI:SS') AS created_at,
  TO_CHAR(last_ddl_time, 'YYYY-MM-DD"T"HH24:MI:SS') AS modified_at,
  status,
  temporary
FROM all_objects
WHERE object_type IN ('TABLE', 'VIEW', 'MATERIALIZED VIEW')
ORDER BY owner, object_name, object_type;
