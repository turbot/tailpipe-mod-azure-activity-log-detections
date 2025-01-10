locals {
  activity_log_iam_detection_common_tags = merge(local.activity_log_detection_common_tags, {
    service = "Azure/IAM"
  })
}

benchmark "activity_logs_iam_detections" {
  title       = "IAM Detections"
  description = "This detection benchmark contains recommendations when scanning Azure IAM activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_authorization_role_assignments_writes,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
  })
}

detection "activity_logs_detect_authorization_role_assignments_writes" {
  title       = "Detect Authorization Role Assignments Writes"
  description = "Detects the granting of permissions to an account, providing visibility into significant changes that may impact security."
  severity    = "medium"
  query       = query.activity_logs_detect_authorization_role_assignments_writes


  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "activity_logs_detect_authorization_role_assignments_writes" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Authorization/roleAssignments/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
