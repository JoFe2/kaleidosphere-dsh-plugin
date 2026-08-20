SELECT
  s.name AS schema_name,
  o.name AS relation_name,
  CASE o.type WHEN N'U' THEN N'TABLE' WHEN N'V' THEN N'VIEW' END AS relation_kind,
  o.object_id,
  CONVERT(nvarchar(33), o.create_date, 126) AS created_at,
  CONVERT(nvarchar(33), o.modify_date, 126) AS modified_at,
  o.is_ms_shipped
FROM sys.objects AS o
INNER JOIN sys.schemas AS s ON s.schema_id = o.schema_id
WHERE o.type IN (N'U', N'V')
  AND o.is_ms_shipped = 0
ORDER BY s.name, o.name, relation_kind;
