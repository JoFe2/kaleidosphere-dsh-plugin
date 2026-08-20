SELECT
  s.name AS schema_name,
  t.name AS relation_name,
  kc.name AS constraint_name,
  CASE kc.type WHEN N'PK' THEN N'PRIMARY_KEY' ELSE N'UNIQUE' END AS constraint_kind,
  c.name AS column_name,
  ic.key_ordinal AS ordinal_position,
  CAST(NULL AS nvarchar(128)) AS referenced_schema_name,
  CAST(NULL AS nvarchar(128)) AS referenced_relation_name,
  CAST(NULL AS nvarchar(128)) AS referenced_column_name,
  CAST(NULL AS nvarchar(max)) AS check_expression,
  CAST(NULL AS nvarchar(60)) AS delete_rule,
  CAST(NULL AS nvarchar(60)) AS update_rule,
  CONVERT(bit, CASE i.is_disabled WHEN 1 THEN 0 ELSE 1 END) AS is_enabled,
  CONVERT(bit, 1) AS is_validated,
  CONVERT(bit, 0) AS is_deferrable,
  CONVERT(bit, 0) AS is_initially_deferred
FROM sys.key_constraints AS kc
INNER JOIN sys.tables AS t ON t.object_id = kc.parent_object_id
INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id
INNER JOIN sys.indexes AS i ON i.object_id = kc.parent_object_id AND i.index_id = kc.unique_index_id
INNER JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.key_ordinal > 0
INNER JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
WHERE t.is_ms_shipped = 0
UNION ALL
SELECT
  s.name AS schema_name,
  t.name AS relation_name,
  fk.name AS constraint_name,
  N'FOREIGN_KEY' AS constraint_kind,
  c.name AS column_name,
  fkc.constraint_column_id AS ordinal_position,
  rs.name AS referenced_schema_name,
  rt.name AS referenced_relation_name,
  rc.name AS referenced_column_name,
  CAST(NULL AS nvarchar(max)) AS check_expression,
  fk.delete_referential_action_desc AS delete_rule,
  fk.update_referential_action_desc AS update_rule,
  CONVERT(bit, CASE fk.is_disabled WHEN 1 THEN 0 ELSE 1 END) AS is_enabled,
  CONVERT(bit, CASE fk.is_not_trusted WHEN 1 THEN 0 ELSE 1 END) AS is_validated,
  CONVERT(bit, 0) AS is_deferrable,
  CONVERT(bit, 0) AS is_initially_deferred
FROM sys.foreign_keys AS fk
INNER JOIN sys.foreign_key_columns AS fkc ON fkc.constraint_object_id = fk.object_id
INNER JOIN sys.tables AS t ON t.object_id = fk.parent_object_id
INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id
INNER JOIN sys.columns AS c ON c.object_id = fkc.parent_object_id AND c.column_id = fkc.parent_column_id
INNER JOIN sys.tables AS rt ON rt.object_id = fk.referenced_object_id
INNER JOIN sys.schemas AS rs ON rs.schema_id = rt.schema_id
INNER JOIN sys.columns AS rc ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id
WHERE t.is_ms_shipped = 0
UNION ALL
SELECT
  s.name AS schema_name,
  t.name AS relation_name,
  chk.name AS constraint_name,
  N'CHECK' AS constraint_kind,
  c.name AS column_name,
  CAST(NULL AS int) AS ordinal_position,
  CAST(NULL AS nvarchar(128)) AS referenced_schema_name,
  CAST(NULL AS nvarchar(128)) AS referenced_relation_name,
  CAST(NULL AS nvarchar(128)) AS referenced_column_name,
  chk.definition AS check_expression,
  CAST(NULL AS nvarchar(60)) AS delete_rule,
  CAST(NULL AS nvarchar(60)) AS update_rule,
  CONVERT(bit, CASE chk.is_disabled WHEN 1 THEN 0 ELSE 1 END) AS is_enabled,
  CONVERT(bit, CASE chk.is_not_trusted WHEN 1 THEN 0 ELSE 1 END) AS is_validated,
  CONVERT(bit, 0) AS is_deferrable,
  CONVERT(bit, 0) AS is_initially_deferred
FROM sys.check_constraints AS chk
INNER JOIN sys.tables AS t ON t.object_id = chk.parent_object_id
INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id
LEFT JOIN sys.columns AS c ON c.object_id = chk.parent_object_id AND c.column_id = NULLIF(chk.parent_column_id, 0)
WHERE t.is_ms_shipped = 0
ORDER BY schema_name, relation_name, constraint_kind, constraint_name, ordinal_position, column_name;
