SELECT
  'SYSTEM:' || privilege AS permission_name,
  1 AS has_permission
FROM session_privs
UNION ALL
SELECT
  'OBJECT:' || privilege || ':' || table_schema || '.' || table_name AS permission_name,
  1 AS has_permission
FROM all_tab_privs
WHERE grantee = SYS_CONTEXT('USERENV', 'SESSION_USER')
UNION ALL
SELECT
  'COLUMN_OBJECT:' || privilege || ':' || table_schema || '.' || table_name || '.' || column_name AS permission_name,
  1 AS has_permission
FROM all_col_privs
WHERE grantee = SYS_CONTEXT('USERENV', 'SESSION_USER')
UNION ALL
SELECT
  'ROLE_OBJECT:' || rtp.privilege || ':' || rtp.owner || '.' || rtp.table_name AS permission_name,
  1 AS has_permission
FROM role_tab_privs rtp
INNER JOIN session_roles sr ON sr.role = rtp.role
ORDER BY permission_name;
