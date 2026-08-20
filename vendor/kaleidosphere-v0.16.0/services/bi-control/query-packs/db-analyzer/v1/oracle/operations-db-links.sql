SELECT
  link.owner AS schema_name,
  link.db_link AS db_link_name,
  TO_CHAR(link.created, 'YYYY-MM-DD"T"HH24:MI:SS') AS created_at,
  CASE WHEN link.host IS NULL THEN NULL ELSE LOWER(STANDARD_HASH(link.host, 'SHA256')) END AS target_host_sha256,
  CASE WHEN link.host IS NULL THEN 'NO_HOST_VISIBLE' ELSE 'SHA256_OF_HOST_NO_CREDENTIALS' END AS target_host_policy,
  'USERNAME_AND_PASSWORD_NOT_EMITTED' AS credential_policy
FROM all_db_links link
ORDER BY link.owner, link.db_link;
