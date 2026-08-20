SELECT
  s.name AS schema_name,
  seq.name AS sequence_name,
  ty.name AS data_type,
  seq.precision AS numeric_precision,
  seq.scale AS numeric_scale,
  CONVERT(nvarchar(128), seq.start_value) AS start_value,
  CONVERT(nvarchar(128), seq.increment) AS increment_by,
  CONVERT(nvarchar(128), seq.minimum_value) AS min_value,
  CONVERT(nvarchar(128), seq.maximum_value) AS max_value,
  CONVERT(bit, seq.is_cycling) AS is_cycling,
  seq.cache_size,
  CONVERT(nvarchar(128), seq.current_value) AS observed_value,
  N'CURRENT_VALUE' AS observed_value_semantics
FROM sys.sequences AS seq
INNER JOIN sys.schemas AS s ON s.schema_id = seq.schema_id
INNER JOIN sys.types AS ty ON ty.user_type_id = seq.user_type_id
ORDER BY s.name, seq.name;
