SELECT
  s.name AS schema_name,
  t.name AS relation_name,
  i.name AS index_name,
  i.type_desc AS index_kind,
  c.name AS column_name,
  ic.index_column_id AS ordinal_position,
  CAST(NULL AS nvarchar(max)) AS column_expression,
  CONVERT(bit, ic.is_included_column) AS is_included,
  CONVERT(bit, CASE WHEN ic.partition_ordinal > 0 THEN 1 ELSE 0 END) AS is_partition_key,
  NULLIF(ic.partition_ordinal, 0) AS partition_ordinal,
  CONVERT(bit, i.is_unique) AS is_unique,
  CONVERT(bit, i.is_primary_key) AS is_primary_key,
  CONVERT(bit, i.is_unique_constraint) AS is_unique_constraint,
  CONVERT(bit, CASE i.is_disabled WHEN 1 THEN 0 ELSE 1 END) AS is_enabled,
  i.filter_definition AS filter_expression,
  ds.name AS data_space_name,
  CASE WHEN ps.data_space_id IS NULL THEN N'NONE' ELSE N'RANGE' END AS partitioning_kind,
  (SELECT COUNT(DISTINCT p.partition_number)
   FROM sys.partitions AS p
   WHERE p.object_id = i.object_id AND p.index_id = i.index_id) AS partition_count
FROM sys.indexes AS i
INNER JOIN sys.tables AS t ON t.object_id = i.object_id
INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id
INNER JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
INNER JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
LEFT JOIN sys.data_spaces AS ds ON ds.data_space_id = i.data_space_id
LEFT JOIN sys.partition_schemes AS ps ON ps.data_space_id = i.data_space_id
WHERE t.is_ms_shipped = 0
  AND i.type IN (1, 2)
  AND i.is_hypothetical = 0
ORDER BY s.name, t.name, i.name, ic.index_column_id, c.name;
