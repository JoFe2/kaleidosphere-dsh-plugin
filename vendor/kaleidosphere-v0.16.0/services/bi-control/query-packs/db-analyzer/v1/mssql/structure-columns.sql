SELECT
  s.name AS schema_name,
  o.name AS relation_name,
  CASE o.type WHEN N'U' THEN N'TABLE' WHEN N'V' THEN N'VIEW' END AS relation_kind,
  c.name AS column_name,
  c.column_id AS ordinal_position,
  ts.name AS data_type_schema,
  t.name AS data_type,
  c.max_length,
  c.precision AS numeric_precision,
  c.scale AS numeric_scale,
  c.is_nullable,
  dc.definition AS default_expression,
  CASE WHEN c.is_computed = 1 THEN N'COMPUTED' WHEN c.is_identity = 1 THEN N'IDENTITY' ELSE N'NONE' END AS generation_kind,
  cc.definition AS generation_expression,
  c.is_identity,
  CONVERT(nvarchar(128), ic.seed_value) AS identity_seed,
  CONVERT(nvarchar(128), ic.increment_value) AS identity_increment,
  CAST(NULL AS nvarchar(128)) AS identity_generation,
  CAST(NULL AS nvarchar(4000)) AS identity_options
FROM sys.columns AS c
INNER JOIN sys.objects AS o ON o.object_id = c.object_id
INNER JOIN sys.schemas AS s ON s.schema_id = o.schema_id
INNER JOIN sys.types AS t ON t.user_type_id = c.user_type_id
INNER JOIN sys.schemas AS ts ON ts.schema_id = t.schema_id
LEFT JOIN sys.default_constraints AS dc ON dc.object_id = c.default_object_id
LEFT JOIN sys.computed_columns AS cc ON cc.object_id = c.object_id AND cc.column_id = c.column_id
LEFT JOIN sys.identity_columns AS ic ON ic.object_id = c.object_id AND ic.column_id = c.column_id
WHERE o.type IN (N'U', N'V')
  AND o.is_ms_shipped = 0
ORDER BY s.name, o.name, c.column_id, c.name;
