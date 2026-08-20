SELECT
  owner AS schema_name,
  job_name AS object_name,
  'SCHEDULER_JOB' AS object_kind,
  CAST(enabled AS VARCHAR2(32)) AS enabled,
  state AS status,
  job_type AS type_name,
  job_class AS class_name,
  program_name,
  schedule_name,
  CAST(NULL AS VARCHAR2(4000)) AS repeat_interval,
  TO_CHAR(start_date, 'YYYY-MM-DD"T"HH24:MI:SS') AS start_at,
  TO_CHAR(next_run_date, 'YYYY-MM-DD"T"HH24:MI:SS') AS next_run_at,
  TO_CHAR(last_start_date, 'YYYY-MM-DD"T"HH24:MI:SS') AS last_start_at,
  TO_CHAR(last_run_duration) AS last_run_duration,
  run_count,
  failure_count,
  'JOB_ACTION_NOT_EMITTED' AS sensitive_fields_policy
FROM all_scheduler_jobs
UNION ALL
SELECT
  owner AS schema_name,
  program_name AS object_name,
  'SCHEDULER_PROGRAM' AS object_kind,
  CAST(enabled AS VARCHAR2(32)) AS enabled,
  CAST(NULL AS VARCHAR2(128)) AS status,
  program_type AS type_name,
  CAST(NULL AS VARCHAR2(128)) AS class_name,
  program_name,
  CAST(NULL AS VARCHAR2(128)) AS schedule_name,
  CAST(NULL AS VARCHAR2(4000)) AS repeat_interval,
  CAST(NULL AS VARCHAR2(32)) AS start_at,
  CAST(NULL AS VARCHAR2(32)) AS next_run_at,
  CAST(NULL AS VARCHAR2(32)) AS last_start_at,
  CAST(NULL AS VARCHAR2(128)) AS last_run_duration,
  number_of_arguments AS run_count,
  CAST(NULL AS NUMBER) AS failure_count,
  'PROGRAM_ACTION_NOT_EMITTED' AS sensitive_fields_policy
FROM all_scheduler_programs
UNION ALL
SELECT
  owner AS schema_name,
  schedule_name AS object_name,
  'SCHEDULER_SCHEDULE' AS object_kind,
  CAST(NULL AS VARCHAR2(32)) AS enabled,
  CAST(NULL AS VARCHAR2(128)) AS status,
  schedule_type AS type_name,
  CAST(NULL AS VARCHAR2(128)) AS class_name,
  CAST(NULL AS VARCHAR2(128)) AS program_name,
  schedule_name,
  repeat_interval,
  TO_CHAR(start_date, 'YYYY-MM-DD"T"HH24:MI:SS') AS start_at,
  CAST(NULL AS VARCHAR2(32)) AS next_run_at,
  CAST(NULL AS VARCHAR2(32)) AS last_start_at,
  CAST(NULL AS VARCHAR2(128)) AS last_run_duration,
  CAST(NULL AS NUMBER) AS run_count,
  CAST(NULL AS NUMBER) AS failure_count,
  'SCHEDULE_TIMING_ONLY' AS sensitive_fields_policy
FROM all_scheduler_schedules
ORDER BY schema_name, object_kind, object_name;
