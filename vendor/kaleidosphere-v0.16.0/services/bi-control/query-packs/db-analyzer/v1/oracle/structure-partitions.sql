SELECT
  pt.owner AS schema_name,
  pt.table_name AS relation_name,
  'TABLE' AS relation_kind,
  'TABLE_PARTITIONING' AS partition_scope,
  CAST(NULL AS VARCHAR2(128)) AS partition_name,
  CAST(NULL AS VARCHAR2(128)) AS subpartition_name,
  pt.partitioning_type,
  pt.subpartitioning_type,
  pt.partition_count,
  CAST(NULL AS NUMBER) AS subpartition_count,
  pkc.column_name AS partition_key_column,
  pkc.column_position AS partition_key_ordinal,
  CAST(NULL AS VARCHAR2(128)) AS tablespace_name,
  CAST(NULL AS NUMBER) AS num_rows_estimate,
  CAST(NULL AS NUMBER) AS blocks_estimate,
  CAST(NULL AS VARCHAR2(32)) AS last_analyzed
FROM all_part_tables pt
LEFT JOIN all_part_key_columns pkc
  ON pkc.owner = pt.owner
  AND pkc.name = pt.table_name
  AND pkc.object_type = 'TABLE'
UNION ALL
SELECT
  tp.table_owner AS schema_name,
  tp.table_name AS relation_name,
  'TABLE' AS relation_kind,
  'TABLE_PARTITION' AS partition_scope,
  tp.partition_name,
  CAST(NULL AS VARCHAR2(128)) AS subpartition_name,
  CAST(NULL AS VARCHAR2(128)) AS partitioning_type,
  CAST(NULL AS VARCHAR2(128)) AS subpartitioning_type,
  CAST(NULL AS NUMBER) AS partition_count,
  tp.subpartition_count,
  CAST(NULL AS VARCHAR2(128)) AS partition_key_column,
  CAST(NULL AS NUMBER) AS partition_key_ordinal,
  tp.tablespace_name,
  tp.num_rows AS num_rows_estimate,
  tp.blocks AS blocks_estimate,
  TO_CHAR(tp.last_analyzed, 'YYYY-MM-DD"T"HH24:MI:SS') AS last_analyzed
FROM all_tab_partitions tp
UNION ALL
SELECT
  tsp.table_owner AS schema_name,
  tsp.table_name AS relation_name,
  'TABLE' AS relation_kind,
  'TABLE_SUBPARTITION' AS partition_scope,
  tsp.partition_name,
  tsp.subpartition_name,
  CAST(NULL AS VARCHAR2(128)) AS partitioning_type,
  CAST(NULL AS VARCHAR2(128)) AS subpartitioning_type,
  CAST(NULL AS NUMBER) AS partition_count,
  CAST(NULL AS NUMBER) AS subpartition_count,
  CAST(NULL AS VARCHAR2(128)) AS partition_key_column,
  CAST(NULL AS NUMBER) AS partition_key_ordinal,
  tsp.tablespace_name,
  tsp.num_rows AS num_rows_estimate,
  tsp.blocks AS blocks_estimate,
  TO_CHAR(tsp.last_analyzed, 'YYYY-MM-DD"T"HH24:MI:SS') AS last_analyzed
FROM all_tab_subpartitions tsp
ORDER BY schema_name, relation_name, partition_scope, partition_name, subpartition_name, partition_key_ordinal;
