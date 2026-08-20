SELECT
  arg.owner AS schema_name,
  COALESCE(arg.package_name, arg.object_name) AS object_name,
  arg.package_name,
  arg.object_name AS subprogram_name,
  arg.argument_name,
  arg.position,
  arg.sequence,
  arg.data_level,
  arg.data_type,
  arg.type_owner,
  arg.type_name,
  arg.type_subname,
  arg.in_out,
  arg.defaulted,
  CASE arg.defaulted WHEN 'Y' THEN 'DEFAULT_EXISTS_VALUE_NOT_EMITTED' ELSE 'NO_DEFAULT' END AS default_value_policy
FROM all_arguments arg
ORDER BY arg.owner, COALESCE(arg.package_name, arg.object_name), arg.object_name, arg.sequence, arg.position, arg.argument_name;
