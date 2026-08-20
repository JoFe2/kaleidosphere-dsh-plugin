SELECT
  seq.sequence_owner AS schema_name,
  seq.sequence_name,
  'NUMBER' AS data_type,
  CAST(NULL AS NUMBER) AS numeric_precision,
  CAST(NULL AS NUMBER) AS numeric_scale,
  CAST(NULL AS VARCHAR2(128)) AS start_value,
  TO_CHAR(seq.increment_by, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''') AS increment_by,
  TO_CHAR(seq.min_value, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''') AS min_value,
  TO_CHAR(seq.max_value, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''') AS max_value,
  CASE seq.cycle_flag WHEN 'Y' THEN 1 ELSE 0 END AS is_cycling,
  seq.cache_size,
  TO_CHAR(seq.last_number, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''') AS observed_value,
  'LAST_NUMBER' AS observed_value_semantics
FROM all_sequences seq
ORDER BY seq.sequence_owner, seq.sequence_name;
