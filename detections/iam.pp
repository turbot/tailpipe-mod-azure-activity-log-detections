locals {
  iam_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/IAM"
  })
}

benchmark "iam_detections" {
  title       = "IAM Detections"
  description = "This detection benchmark contains recommendations when scanning Azure IAM activity logs."
  type        = "detection"
  children = [
    detection.detect_iam_authorization_role_assignment_updates,
  ]

  tags = merge(local.iam_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_iam_authorization_role_assignment_updates" {
  title           = "Detect IAM Authorization Role Assignment Updates"
  description     = "Detect when Azure role assignments are updated, providing visibility into significant changes that may impact security."
  documentation   = file("./detections/docs/detect_iam_authorization_role_assignment_updates.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_iam_authorization_role_assignment_updates


  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

query "detect_iam_authorization_role_assignment_updates" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Authorization/roleAssignments/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
