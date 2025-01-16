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
    detection.detect_sql_server_deletions,
    detection.detect_sql_firewall_rule_updates,
    detection.detect_sql_database_deletions,
    detection.detect_sql_role_assignment_updates,
    detection.detect_sql_tde_updates
  ]

  tags = merge(local.sql_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_sql_server_deletions" {
  title           = "Detect SQL Server Deletions"
  description     = "Detect the deletions of Azure SQL Servers, providing visibility into significant changes that may impact automation and orchestration."
  documentation   = file("./detections/docs/detect_sql_server_deletions.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_sql_server_deletions

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "detect_sql_firewall_rule_updates" {
  title           = "Detect SQL Server Firewall Rule Updates"
  description     = "Detect Azure SQL Servers to check for firewall rule updates, which may expose the server to unauthorized connections."
  documentation   = file("./detections/docs/detect_sql_firewall_rule_updates.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_sql_firewall_rule_updates

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0005:T1562.007"
  })
}

detection "detect_sql_database_deletions" {
  title           = "Detect SQL Database Deletions"
  description     = "Detect Azure SQL Databases to check for deletions that may result in data loss or service disruption."
  documentation   = file("./detections/docs/detect_sql_database_deletions.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_sql_database_deletions

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "detect_sql_role_assignment_updates" {
  title           = "Detect SQL Server Role Assignment Changes"
  description     = "Detect Azure SQL Servers to check for role assignment changes, which may grant elevated privileges."
  documentation   = file("./detections/docs/detect_sql_role_assignment_updates.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_sql_role_assignment_updates

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

detection "detect_sql_tde_updates" {
  title           = "Detect SQL Database TDE Updates"
  description     = "Detect Azure SQL Databases to check for Transparent Data Encryption (TDE) updates, which may expose sensitive data."
  documentation   = file("./detections/docs/detect_sql_tde_updates.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_sql_tde_updates

  tags = merge(local.sql_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "detect_sql_tde_updates" {
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

query "detect_sql_role_assignment_updates" {
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

query "detect_sql_database_deletions" {
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

query "detect_sql_firewall_rule_updates" {
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

query "detect_sql_server_deletions" {
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