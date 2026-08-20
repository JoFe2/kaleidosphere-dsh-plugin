SELECT
  requested.permission_name,
  CAST(HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', requested.permission_name) AS int) AS has_permission
FROM (VALUES
  (N'CONNECT'),
  (N'VIEW DEFINITION')
) AS requested(permission_name)
ORDER BY requested.permission_name;
