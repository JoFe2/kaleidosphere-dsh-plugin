SELECT
  collector_id,
  capability_name,
  visibility_state,
  minimum_privilege,
  fallback_semantics
FROM (
  SELECT 'oracle.structure.relations' AS collector_id, 'ALL_OBJECTS scoped TABLE/VIEW/MATERIALIZED VIEW metadata' AS capability_name, 'PROBED_BY_COLLECTOR' AS visibility_state, 'CREATE SESSION plus object metadata visibility' AS minimum_privilege, 'DENIED/TIMEOUT/ERROR means unknown, not empty' AS fallback_semantics FROM product_component_version
  UNION ALL SELECT 'oracle.structure.columns', 'ALL_TAB_COLS column metadata without row samples', 'PROBED_BY_COLLECTOR', 'metadata visibility on scoped objects', 'DENIED/TIMEOUT/ERROR means unknown, not empty' FROM product_component_version
  UNION ALL SELECT 'oracle.inventory.statistics', 'ALL_TAB_STATISTICS and ALL_IND_STATISTICS estimates', 'PROBED_BY_COLLECTOR', 'statistics visibility on scoped objects', 'NUM_ROWS is an optimizer estimate, never COUNT(*)' FROM product_component_version
  UNION ALL SELECT 'oracle.inventory.sizes', 'segment/block/tablespace metadata where dictionary visibility permits', 'PROBED_BY_COLLECTOR', 'segment metadata visibility', 'DENIED/TIMEOUT/ERROR means size unknown' FROM product_component_version
  UNION ALL SELECT 'oracle.stored.logic', 'stored object signatures, status, hashes, errors and native dependencies', 'PROBED_BY_COLLECTOR', 'metadata/source visibility on scoped stored objects', 'raw source is never emitted' FROM product_component_version
  UNION ALL SELECT 'oracle.operations.scheduler', 'scheduler and materialized-view refresh metadata', 'PROBED_BY_COLLECTOR', 'scheduler/MVIEW metadata visibility', 'secrets and job action text are not emitted' FROM product_component_version
)
ORDER BY collector_id;
