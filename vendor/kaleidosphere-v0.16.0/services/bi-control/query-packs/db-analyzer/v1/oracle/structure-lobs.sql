SELECT
  lob.owner AS schema_name,
  lob.table_name AS relation_name,
  lob.column_name,
  lob.segment_name,
  lob.tablespace_name,
  lob.securefile,
  lob.compression,
  lob.deduplication,
  lob.encrypt AS encryption,
  lob.in_row,
  lob.chunk,
  lob.retention,
  lob.cache,
  lob.logging
FROM all_lobs lob
ORDER BY lob.owner, lob.table_name, lob.column_name, lob.segment_name;
