SELECT
  tab.owner AS schema_name,
  tab.table_name AS segment_name,
  CAST(NULL AS VARCHAR2(128)) AS partition_name,
  'TABLE_OR_MATERIALIZED_VIEW' AS segment_type,
  tab.tablespace_name,
  CAST(NULL AS NUMBER) AS bytes,
  tab.blocks,
  CAST(NULL AS NUMBER) AS extents,
  'VISIBLE_TABLE_BLOCK_METADATA_BYTES_NOT_VISIBLE' AS size_semantics
FROM all_tables tab
UNION ALL
SELECT
  part.table_owner AS schema_name,
  part.table_name AS segment_name,
  part.partition_name,
  'TABLE_PARTITION' AS segment_type,
  part.tablespace_name,
  CAST(NULL AS NUMBER) AS bytes,
  part.blocks,
  CAST(NULL AS NUMBER) AS extents,
  'VISIBLE_PARTITION_BLOCK_METADATA_BYTES_NOT_VISIBLE' AS size_semantics
FROM all_tab_partitions part
UNION ALL
SELECT
  idx.owner AS schema_name,
  idx.index_name AS segment_name,
  CAST(NULL AS VARCHAR2(128)) AS partition_name,
  'INDEX' AS segment_type,
  idx.tablespace_name,
  CAST(NULL AS NUMBER) AS bytes,
  idx.leaf_blocks AS blocks,
  CAST(NULL AS NUMBER) AS extents,
  'VISIBLE_INDEX_LEAF_BLOCK_METADATA_BYTES_NOT_VISIBLE' AS size_semantics
FROM all_indexes idx
UNION ALL
SELECT
  lob.owner AS schema_name,
  lob.segment_name,
  CAST(NULL AS VARCHAR2(128)) AS partition_name,
  'LOB' AS segment_type,
  lob.tablespace_name,
  CAST(NULL AS NUMBER) AS bytes,
  CAST(NULL AS NUMBER) AS blocks,
  CAST(NULL AS NUMBER) AS extents,
  'VISIBLE_LOB_METADATA_BYTES_NOT_VISIBLE' AS size_semantics
FROM all_lobs lob
ORDER BY schema_name, segment_type, segment_name, partition_name;
