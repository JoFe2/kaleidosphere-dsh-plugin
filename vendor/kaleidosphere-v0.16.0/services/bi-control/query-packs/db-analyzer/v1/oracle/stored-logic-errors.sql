SELECT
  err.owner AS schema_name,
  err.name AS object_name,
  err.type AS object_kind,
  err.sequence,
  err.line,
  err.position,
  err.attribute,
  err.message_number,
  LENGTH(err.text) AS error_text_length,
  LOWER(STANDARD_HASH(err.text, 'SHA256')) AS error_text_sha256,
  'SHA256_OF_COMPILE_ERROR_TEXT' AS error_hash_algorithm
FROM all_errors err
ORDER BY err.owner, err.name, err.type, err.sequence;
