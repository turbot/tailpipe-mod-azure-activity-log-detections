locals {
  iam_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    folder  = "IAM"
    service = "Azure/IAM"
  })
}

benchmark "iam_detections" {
  title       = "IAM Detections"
  description = "This detection benchmark contains recommendations when scanning Azure IAM activity logs."
  type        = "detection"
  children = [
    detection.iam_role_assignment_created_or_updated,
  ]

  tags = merge(local.iam_common_tags, {
    type = "Benchmark"
  })
}

detection "iam_role_assignment_created_or_updated" {
  title           = "IAM Role Assignment Created or Updated"
  description     = "Detect when an Azure IAM role assignment was created or updated, providing visibility into significant changes that may impact security, such as unauthorized access or privilege escalation."
  documentation   = file("./detections/docs/iam_role_assignment_created_or_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.iam_role_assignment_created_or_updated

  tags = merge(local.iam_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

query "iam_role_assignment_created_or_updated" {
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

  tags = local.iam_common_tags
}
