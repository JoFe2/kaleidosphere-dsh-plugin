SELECT
  dep.owner AS source_schema_name,
  dep.name AS source_object_name,
  dep.type AS source_object_kind,
  dep.referenced_owner AS target_schema_name,
  dep.referenced_name AS target_object_name,
  dep.referenced_type AS target_object_kind,
  dep.referenced_link_name AS target_db_link_name,
  dep.dependency_type AS native_dependency_kind,
  CASE WHEN dep.referenced_owner IS NULL OR dep.referenced_name IS NULL THEN 'UNRESOLVED' ELSE 'RESOLVED' END AS resolution_state,
  'NOT_PROVEN' AS column_resolution_state
FROM all_dependencies dep
WHERE dep.type IN ('PACKAGE', 'PACKAGE BODY', 'PROCEDURE', 'FUNCTION', 'TRIGGER', 'TYPE', 'TYPE BODY', 'VIEW', 'MATERIALIZED VIEW')
ORDER BY dep.owner, dep.name, dep.type, dep.referenced_owner, dep.referenced_name, dep.referenced_type;
