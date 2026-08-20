SELECT
  CAST(N'mssql' AS nvarchar(16)) AS engine,
  CAST(SERVERPROPERTY(N'ProductVersion') AS nvarchar(128)) AS engine_version,
  CAST(SERVERPROPERTY(N'Edition') AS nvarchar(256)) AS engine_edition,
  d.name AS database_name,
  CAST(NULL AS nvarchar(128)) AS container_name,
  d.compatibility_level
FROM sys.databases AS d
WHERE d.name = DB_NAME()
ORDER BY d.name;
