SELECT
  i.table_owner AS schema_name,
  i.table_name AS relation_name,
  i.index_name,
  i.index_type AS index_kind,
  ic.column_name,
  ic.column_position AS ordinal_position,
  ie.column_expression,
  0 AS is_included,
  CASE WHEN pkc.column_position IS NULL THEN 0 ELSE 1 END AS is_partition_key,
  pkc.column_position AS partition_ordinal,
  CASE i.uniqueness WHEN 'UNIQUE' THEN 1 ELSE 0 END AS is_unique,
  CASE c.constraint_type WHEN 'P' THEN 1 ELSE 0 END AS is_primary_key,
  CASE c.constraint_type WHEN 'U' THEN 1 ELSE 0 END AS is_unique_constraint,
  CASE i.status WHEN 'VALID' THEN 1 ELSE 0 END AS is_enabled,
  CAST(NULL AS VARCHAR2(4000)) AS filter_expression,
  i.tablespace_name AS data_space_name,
  COALESCE(pi.partitioning_type, 'NONE') AS partitioning_kind,
  COALESCE(pi.partition_count, 1) AS partition_count
FROM all_indexes i
INNER JOIN all_ind_columns ic
  ON ic.index_owner = i.owner
  AND ic.index_name = i.index_name
  AND ic.table_owner = i.table_owner
  AND ic.table_name = i.table_name
LEFT JOIN all_ind_expressions ie
  ON ie.index_owner = ic.index_owner
  AND ie.index_name = ic.index_name
  AND ie.table_owner = ic.table_owner
  AND ie.table_name = ic.table_name
  AND ie.column_position = ic.column_position
LEFT JOIN all_part_indexes pi
  ON pi.owner = i.owner
  AND pi.index_name = i.index_name
LEFT JOIN all_part_key_columns pkc
  ON pkc.owner = i.owner
  AND pkc.name = i.index_name
  AND pkc.object_type = 'INDEX'
  AND pkc.column_name = ic.column_name
LEFT JOIN all_constraints c
  ON c.owner = i.table_owner
  AND c.table_name = i.table_name
  AND c.index_owner = i.owner
  AND c.index_name = i.index_name
  AND c.constraint_type IN ('P', 'U')
ORDER BY i.table_owner, i.table_name, i.index_name, ic.column_position, ic.column_name;
