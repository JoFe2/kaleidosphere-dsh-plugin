SELECT
  syn.owner AS schema_name,
  syn.synonym_name,
  syn.table_owner || '.' || syn.table_name || CASE WHEN syn.db_link IS NULL THEN NULL ELSE '@' || syn.db_link END AS target_reference,
  CAST(NULL AS VARCHAR2(128)) AS target_catalog_name,
  syn.table_owner AS target_schema_name,
  syn.table_name AS target_object_name,
  syn.db_link AS remote_locator
FROM all_synonyms syn
ORDER BY syn.owner, syn.synonym_name;
