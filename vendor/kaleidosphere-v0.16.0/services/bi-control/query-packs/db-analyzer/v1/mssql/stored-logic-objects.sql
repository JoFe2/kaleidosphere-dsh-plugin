SELECT
  s.name AS schema_name,
  o.name AS object_name,
  CASE
    WHEN o.type IN ('P', 'PC') THEN 'PROCEDURE'
    WHEN o.type IN ('FN', 'FS', 'FT', 'IF', 'TF') THEN 'FUNCTION'
    WHEN o.type IN ('TR', 'TA') THEN 'TRIGGER'
  END AS object_kind,
  CONVERT(varchar(32), o.object_id) AS native_object_id,
  ps.name AS parent_schema_name,
  po.name AS parent_object_name,
  CASE
    WHEN o.type IN ('TR', 'TA') AND tr.is_disabled = 1 THEN 'DISABLED'
    WHEN o.type IN ('TR', 'TA') THEN 'ENABLED'
    ELSE 'NOT_APPLICABLE'
  END AS enablement_state,
  CASE WHEN sm.definition IS NULL THEN 'ENCRYPTED_OR_INVISIBLE' ELSE 'VISIBLE_HASHED' END AS definition_visibility,
  CASE WHEN sm.definition IS NULL THEN NULL ELSE 1 END AS definition_component_ordinal,
  CASE
    WHEN sm.definition IS NULL THEN NULL
    ELSE LOWER(CONVERT(varchar(64), HASHBYTES('SHA2_256', CONVERT(varbinary(max), sm.definition)), 2))
  END AS definition_component_hash,
  CASE WHEN sm.definition IS NULL THEN NULL ELSE 'SHA-256/MSSQL-NVARCHAR-UTF16LE' END AS definition_component_hash_algorithm
FROM sys.objects AS o
JOIN sys.schemas AS s ON s.schema_id = o.schema_id
LEFT JOIN sys.sql_modules AS sm ON sm.object_id = o.object_id
LEFT JOIN sys.triggers AS tr ON tr.object_id = o.object_id
LEFT JOIN sys.objects AS po ON po.object_id = o.parent_object_id AND o.parent_object_id <> 0
LEFT JOIN sys.schemas AS ps ON ps.schema_id = po.schema_id
WHERE o.type IN ('P', 'PC', 'FN', 'FS', 'FT', 'IF', 'TF', 'TR', 'TA')
  AND o.is_ms_shipped = 0;
