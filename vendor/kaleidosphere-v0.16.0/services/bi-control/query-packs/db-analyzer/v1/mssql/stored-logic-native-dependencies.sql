SELECT
  source_schema.name AS source_schema_name,
  source_object.name AS source_object_name,
  CASE
    WHEN source_object.type IN ('P', 'PC') THEN 'PROCEDURE'
    WHEN source_object.type IN ('FN', 'FS', 'FT', 'IF', 'TF') THEN 'FUNCTION'
    WHEN source_object.type IN ('TR', 'TA') THEN 'TRIGGER'
  END AS source_object_kind,
  COALESCE(dependency.referenced_schema_name, target_schema.name) AS target_schema_name,
  COALESCE(dependency.referenced_entity_name, target_object.name) AS target_object_name,
  CASE
    WHEN target_object.type IN ('U') THEN 'TABLE'
    WHEN target_object.type IN ('V') THEN 'VIEW'
    WHEN target_object.type IN ('P', 'PC') THEN 'PROCEDURE'
    WHEN target_object.type IN ('FN', 'FS', 'FT', 'IF', 'TF') THEN 'FUNCTION'
    WHEN target_object.type IN ('TR', 'TA') THEN 'TRIGGER'
    WHEN target_object.type IN ('SO') THEN 'SEQUENCE'
    WHEN target_object.type IN ('SN') THEN 'SYNONYM'
    ELSE NULL
  END AS target_object_kind,
  target_column.name AS target_column_name,
  CASE
    WHEN dependency.referenced_minor_id > 0 AND target_column.column_id IS NOT NULL THEN 'PROVEN'
    ELSE 'NOT_PROVEN'
  END AS column_resolution_state,
  dependency.referenced_database_name AS target_database_name,
  dependency.referenced_server_name AS target_server_or_link_name,
  CASE
    WHEN dependency.referenced_id IS NOT NULL
      AND dependency.referenced_database_name IS NULL
      AND dependency.referenced_server_name IS NULL THEN 'RESOLVED'
    ELSE 'UNRESOLVED'
  END AS resolution_state,
  dependency.referenced_class_desc AS native_dependency_kind,
  dependency.is_schema_bound_reference AS is_schema_bound,
  dependency.is_caller_dependent AS is_caller_dependent
FROM sys.sql_expression_dependencies AS dependency
JOIN sys.objects AS source_object ON source_object.object_id = dependency.referencing_id
JOIN sys.schemas AS source_schema ON source_schema.schema_id = source_object.schema_id
LEFT JOIN sys.objects AS target_object ON target_object.object_id = dependency.referenced_id
LEFT JOIN sys.schemas AS target_schema ON target_schema.schema_id = target_object.schema_id
LEFT JOIN sys.columns AS target_column
  ON target_column.object_id = dependency.referenced_id
  AND target_column.column_id = dependency.referenced_minor_id
WHERE source_object.type IN ('P', 'PC', 'FN', 'FS', 'FT', 'IF', 'TF', 'TR', 'TA')
  AND source_object.is_ms_shipped = 0
  AND dependency.referencing_minor_id = 0;
