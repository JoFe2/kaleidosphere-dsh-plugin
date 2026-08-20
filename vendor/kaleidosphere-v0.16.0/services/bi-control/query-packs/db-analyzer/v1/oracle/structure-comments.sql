SELECT
  tc.owner AS schema_name,
  tc.table_name AS relation_name,
  CAST(NULL AS VARCHAR2(128)) AS column_name,
  'RELATION' AS comment_scope,
  CASE WHEN tc.comments IS NULL THEN 0 ELSE LENGTH(tc.comments) END AS comment_length,
  CASE WHEN tc.comments IS NULL THEN NULL ELSE LOWER(STANDARD_HASH(tc.comments, 'SHA256')) END AS comment_sha256,
  'SHA256_OF_COMMENT_TEXT' AS comment_hash_algorithm
FROM all_tab_comments tc
INNER JOIN all_objects ao
  ON ao.owner = tc.owner
  AND ao.object_name = tc.table_name
  AND ao.object_type IN ('TABLE', 'VIEW', 'MATERIALIZED VIEW')
UNION ALL
SELECT
  cc.owner AS schema_name,
  cc.table_name AS relation_name,
  cc.column_name,
  'COLUMN' AS comment_scope,
  CASE WHEN cc.comments IS NULL THEN 0 ELSE LENGTH(cc.comments) END AS comment_length,
  CASE WHEN cc.comments IS NULL THEN NULL ELSE LOWER(STANDARD_HASH(cc.comments, 'SHA256')) END AS comment_sha256,
  'SHA256_OF_COMMENT_TEXT' AS comment_hash_algorithm
FROM all_col_comments cc
INNER JOIN all_objects ao
  ON ao.owner = cc.owner
  AND ao.object_name = cc.table_name
  AND ao.object_type IN ('TABLE', 'VIEW', 'MATERIALIZED VIEW')
ORDER BY schema_name, relation_name, comment_scope, column_name;
