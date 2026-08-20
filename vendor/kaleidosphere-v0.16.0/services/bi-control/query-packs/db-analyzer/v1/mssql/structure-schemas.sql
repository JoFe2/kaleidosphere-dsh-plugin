SELECT
  s.name AS schema_name,
  s.schema_id,
  USER_NAME(s.principal_id) AS owner_name
FROM sys.schemas AS s
WHERE s.name NOT IN (N'sys', N'INFORMATION_SCHEMA')
ORDER BY s.name;
