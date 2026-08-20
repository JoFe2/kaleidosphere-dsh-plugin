SELECT
  ao.owner AS schema_name,
  ao.object_name,
  ao.object_type AS object_kind,
  ao.object_id AS native_object_id,
  ao.status,
  TO_CHAR(ao.created, 'YYYY-MM-DD"T"HH24:MI:SS') AS created_at,
  TO_CHAR(ao.last_ddl_time, 'YYYY-MM-DD"T"HH24:MI:SS') AS last_ddl_time,
  CASE WHEN trg.trigger_name IS NULL THEN 'NOT_APPLICABLE' ELSE trg.status END AS trigger_status,
  trg.table_owner AS trigger_table_schema_name,
  trg.table_name AS trigger_table_name,
  COUNT(src.line) AS source_line_count,
  CASE WHEN COUNT(src.line) = 0 THEN NULL ELSE LOWER(STANDARD_HASH(LISTAGG(LOWER(STANDARD_HASH(src.text, 'SHA256')), '') WITHIN GROUP (ORDER BY src.line), 'SHA256')) END AS source_hash_sha256,
  CASE WHEN COUNT(src.line) = 0 THEN NULL ELSE 'SHA256_OF_ORDERED_SOURCE_LINE_SHA256_VALUES' END AS source_hash_algorithm,
  CASE WHEN COUNT(src.line) = 0 THEN 'SOURCE_NOT_VISIBLE' ELSE 'LOCAL_HASH_ONLY_RAW_SOURCE_NOT_EMITTED' END AS source_storage_policy,
  CASE WHEN MAX(CASE WHEN LOWER(src.text) LIKE '%wrapped%' THEN 1 ELSE 0 END) = 1 THEN 1 ELSE 0 END AS wrapped_code_blind_spot
FROM all_objects ao
LEFT JOIN all_source src
  ON src.owner = ao.owner
  AND src.name = ao.object_name
  AND src.type = ao.object_type
LEFT JOIN all_triggers trg
  ON trg.owner = ao.owner
  AND trg.trigger_name = ao.object_name
WHERE ao.object_type IN ('PACKAGE', 'PACKAGE BODY', 'PROCEDURE', 'FUNCTION', 'TRIGGER', 'TYPE', 'TYPE BODY')
GROUP BY ao.owner, ao.object_name, ao.object_type, ao.object_id, ao.status, ao.created, ao.last_ddl_time, trg.trigger_name, trg.status, trg.table_owner, trg.table_name
ORDER BY ao.owner, ao.object_name, ao.object_type;
