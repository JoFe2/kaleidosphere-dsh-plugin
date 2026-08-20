SELECT
  used.schema_name,
  used.tablespace_name,
  CAST(NULL AS NUMBER) AS block_size,
  CAST(NULL AS VARCHAR2(128)) AS status,
  CAST(NULL AS VARCHAR2(128)) AS contents,
  CAST(NULL AS VARCHAR2(128)) AS logging,
  CAST(NULL AS VARCHAR2(128)) AS extent_management,
  CAST(NULL AS VARCHAR2(128)) AS allocation_type,
  CAST(NULL AS VARCHAR2(128)) AS segment_space_management,
  COUNT(*) AS visible_object_references
FROM (
  SELECT owner AS schema_name, tablespace_name FROM all_tables WHERE tablespace_name IS NOT NULL
  UNION ALL SELECT owner AS schema_name, tablespace_name FROM all_indexes WHERE tablespace_name IS NOT NULL
  UNION ALL SELECT owner AS schema_name, tablespace_name FROM all_lobs WHERE tablespace_name IS NOT NULL
) used
GROUP BY used.schema_name, used.tablespace_name
ORDER BY used.schema_name, used.tablespace_name;
