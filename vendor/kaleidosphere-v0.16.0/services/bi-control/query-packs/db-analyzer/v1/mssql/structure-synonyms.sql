SELECT
  s.name AS schema_name,
  syn.name AS synonym_name,
  syn.base_object_name AS target_reference,
  PARSENAME(syn.base_object_name, 3) AS target_catalog_name,
  PARSENAME(syn.base_object_name, 2) AS target_schema_name,
  PARSENAME(syn.base_object_name, 1) AS target_object_name,
  PARSENAME(syn.base_object_name, 4) AS remote_locator
FROM sys.synonyms AS syn
INNER JOIN sys.schemas AS s ON s.schema_id = syn.schema_id
ORDER BY s.name, syn.name;
