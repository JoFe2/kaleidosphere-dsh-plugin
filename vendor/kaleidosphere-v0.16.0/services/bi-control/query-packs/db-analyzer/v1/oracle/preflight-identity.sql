SELECT
  'oracle' AS engine,
  pcv.version AS engine_version,
  CAST(NULL AS VARCHAR2(128)) AS engine_edition,
  SYS_CONTEXT('USERENV', 'DB_UNIQUE_NAME') AS database_name,
  SYS_CONTEXT('USERENV', 'CON_NAME') AS container_name,
  CAST(NULL AS NUMBER) AS compatibility_level
FROM product_component_version pcv
WHERE pcv.product LIKE 'Oracle%Database%'
ORDER BY pcv.product;
