SELECT
  ist.owner AS schema_name,
  ist.table_name AS relation_name,
  ist.index_name,
  ist.object_type,
  ist.partition_name,
  ist.subpartition_name,
  ist.num_rows AS num_rows_estimate,
  ist.leaf_blocks,
  ist.distinct_keys,
  ist.clustering_factor,
  ist.sample_size,
  TO_CHAR(ist.last_analyzed, 'YYYY-MM-DD"T"HH24:MI:SS') AS last_analyzed,
  ist.stale_stats,
  'OPTIMIZER_STATISTICS_ESTIMATE' AS row_count_semantics
FROM all_ind_statistics ist
ORDER BY ist.owner, ist.table_name, ist.index_name, ist.object_type, ist.partition_name, ist.subpartition_name;
