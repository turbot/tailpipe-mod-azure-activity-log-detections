locals {
  activity_log_sql_detection_common_tags = merge(local.activity_log_detection_common_tags, {
    service = "Azure/SQL"
  })
}

benchmark "activity_logs_sql_detections" {
  title       = "SQL Detections"
  description = "This detection benchmark contains recommendations when scanning Azure SQL activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_sql_server_deletions,
    detection.activity_logs_detect_sql_firewall_rule_updates,
    detection.activity_logs_detect_sql_database_deletions,
    detection.activity_logs_detect_sql_role_assignment_changes,
    detection.activity_logs_detect_sql_tde_updates
  ]

  tags = merge(local.activity_log_sql_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "activity_logs_detect_sql_server_deletions" {
  title       = "Detect SQL Server Deletions"
  description = "Detect the deletions of Azure SQL Servers, providing visibility into significant changes that may impact automation and orchestration."
  severity    = "low"
  query       = query.activity_logs_detect_sql_server_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "activity_logs_detect_sql_firewall_rule_updates" {
  title       = "Detect SQL Server Firewall Rule Updates"
  description = "Detect Azure SQL Servers to check for firewall rule updates, which may expose the server to unauthorized connections."
  severity    = "medium"
  query       = query.activity_logs_detect_sql_firewall_rule_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.007"
  })
}

detection "activity_logs_detect_sql_database_deletions" {
  title       = "Detect SQL Database Deletions"
  description = "Detect Azure SQL Databases to check for deletions that may result in data loss or service disruption."
  severity    = "high"
  query       = query.activity_logs_detect_sql_database_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "activity_logs_detect_sql_role_assignment_changes" {
  title       = "Detect SQL Server Role Assignment Changes"
  description = "Detect Azure SQL Servers to check for role assignment changes, which may grant elevated privileges."
  severity    = "medium"
  query       = query.activity_logs_detect_sql_role_assignment_changes

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

detection "activity_logs_detect_sql_tde_updates" {
  title       = "Detect SQL Database TDE Updates"
  description = "Detect Azure SQL Databases to check for Transparent Data Encryption (TDE) updates, which may expose sensitive data."
  severity    = "high"
  query       = query.activity_logs_detect_sql_tde_updates

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "activity_logs_detect_sql_tde_updates" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Sql/servers/databases/encryptionProtector/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_sql_role_assignment_changes" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Authorization/roleAssignments/write'
      and resource_type = 'Microsoft.Sql/servers'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_sql_database_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Sql/servers/databases/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_sql_firewall_rule_updates" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Sql/servers/firewallRules/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_sql_server_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Sql/servers/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}