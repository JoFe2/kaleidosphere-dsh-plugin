SELECT
  ts.owner AS schema_name,
  ts.table_name AS relation_name,
  ts.object_type,
  ts.partition_name,
  ts.subpartition_name,
  ts.num_rows AS num_rows_estimate,
  ts.blocks AS blocks_estimate,
  ts.avg_row_len,
  ts.sample_size,
  TO_CHAR(ts.last_analyzed, 'YYYY-MM-DD"T"HH24:MI:SS') AS last_analyzed,
  ts.stale_stats,
  'OPTIMIZER_STATISTICS_ESTIMATE' AS row_count_semantics
FROM all_tab_statistics ts
ORDER BY ts.owner, ts.table_name, ts.object_type, ts.partition_name, ts.subpartition_name;
