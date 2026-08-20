SELECT
  tc.owner AS schema_name,
  tc.table_name AS relation_name,
  ao.object_type AS relation_kind,
  tc.column_name,
  tc.column_id AS ordinal_position,
  tc.data_type_owner AS data_type_schema,
  tc.data_type,
  tc.data_length AS max_length,
  tc.data_precision AS numeric_precision,
  tc.data_scale AS numeric_scale,
  CASE tc.nullable WHEN 'Y' THEN 1 ELSE 0 END AS is_nullable,
  CASE WHEN tc.virtual_column = 'NO' THEN tc.data_default_vc END AS default_expression,
  CASE WHEN tc.virtual_column = 'YES' THEN 'VIRTUAL' WHEN idc.column_name IS NOT NULL THEN 'IDENTITY' ELSE 'NONE' END AS generation_kind,
  CASE WHEN tc.virtual_column = 'YES' THEN tc.data_default_vc END AS generation_expression,
  CASE WHEN idc.column_name IS NOT NULL THEN 1 ELSE 0 END AS is_identity,
  CAST(NULL AS VARCHAR2(128)) AS identity_seed,
  CAST(NULL AS VARCHAR2(128)) AS identity_increment,
  idc.generation_type AS identity_generation,
  idc.identity_options
FROM all_tab_cols tc
INNER JOIN all_objects ao
  ON ao.owner = tc.owner
  AND ao.object_name = tc.table_name
  AND ao.object_type IN ('TABLE', 'VIEW', 'MATERIALIZED VIEW')
LEFT JOIN all_tab_identity_cols idc
  ON idc.owner = tc.owner
  AND idc.table_name = tc.table_name
  AND idc.column_name = tc.column_name
ORDER BY tc.owner, tc.table_name, tc.column_id, tc.column_name;
