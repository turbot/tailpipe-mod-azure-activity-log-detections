locals {
  sql_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/SQL"
  })
}

benchmark "sql_detections" {
  title       = "SQL Detections"
  description = "This detection benchmark contains recommendations when scanning Azure SQL activity logs."
  type        = "detection"
  children = [
    detection.sql_database_deleted,
    detection.sql_database_tde_created_or_updated,
    detection.sql_server_deleted,
    detection.sql_server_firewall_rule_created_or_updated,
    detection.sql_server_role_assignment_created_or_updated,
  ]

  tags = merge(local.sql_common_tags, {
    type = "Benchmark"
  })
}

detection "sql_server_deleted" {
  title           = "SQL Server Deleted"
  description     = "Detect when an Azure SQL Server was deleted, potentially disrupting database operations, impacting automation and orchestration workflows, and leading to the loss of critical data or configurations."
  documentation   = file("./detections/docs/sql_server_deleted.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.sql_server_deleted

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "sql_server_firewall_rule_created_or_updated" {
  title           = "SQL Server Firewall Rule Created or Updated"
  description     = "Detect when an Azure SQL Server firewall rule was created or updated, which may expose the server to unauthorized connections by altering access controls or allowing unrestricted IP ranges."
  documentation   = file("./detections/docs/sql_server_firewall_rule_created_or_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.sql_server_firewall_rule_created_or_updated

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0005:T1562.007"
  })
}

detection "sql_database_deleted" {
  title           = "SQL Database Deleted"
  description     = "Detect when an Azure SQL Database was deleted, potentially resulting in data loss, service disruption, and impact to critical operations or applications."
  documentation   = file("./detections/docs/sql_database_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.sql_database_deleted

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "sql_server_role_assignment_created_or_updated" {
  title           = "SQL Server Role Assignment Created or Updated"
  description     = "Detect when an Azure SQL Server role assignment was created or updated, which may grant elevated privileges or unauthorized access, potentially impacting the security of databases and sensitive data."
  documentation   = file("./detections/docs/sql_server_role_assignment_created_or_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.sql_server_role_assignment_created_or_updated

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

detection "sql_database_tde_created_or_updated" {
  title           = "SQL Database TDE Created or Updated"
  description     = "Detect when Transparent Data Encryption (TDE) was created or updated for an Azure SQL Database, which may expose sensitive data by disabling encryption or altering encryption settings."
  documentation   = file("./detections/docs/sql_database_tde_created_or_updated.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.sql_database_tde_created_or_updated

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "sql_database_tde_created_or_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Sql/servers/databases/encryptionProtector/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "sql_server_role_assignment_created_or_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Authorization/roleAssignments/write'
      and resource_type = 'Microsoft.Sql/servers'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "sql_database_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Sql/servers/databases/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "sql_server_firewall_rule_created_or_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Sql/servers/firewallRules/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "sql_server_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Sql/servers/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}