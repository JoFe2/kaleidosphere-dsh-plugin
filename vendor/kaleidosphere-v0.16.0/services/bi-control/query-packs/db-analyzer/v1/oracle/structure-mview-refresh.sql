SELECT
  mv.owner AS schema_name,
  mv.mview_name AS relation_name,
  mv.container_name,
  mv.build_mode,
  mv.refresh_mode,
  mv.refresh_method,
  mv.fast_refreshable,
  TO_CHAR(mv.last_refresh_date, 'YYYY-MM-DD"T"HH24:MI:SS') AS last_refresh_date,
  mv.last_refresh_type,
  mv.staleness,
  mv.compile_state
FROM all_mviews mv
ORDER BY mv.owner, mv.mview_name;
