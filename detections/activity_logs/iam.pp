detection_benchmark "activity_logs_iam_detections" {
  title = "Activity Log IAM Detections"
  description = "This detection benchmark contains recommendations when scanning Azure IAM activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_grant_permissions_detection,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/IAM"
  })
}

detection "activity_logs_detect_grant_permissions_detection" {
  title       = "Detect Permission Granted to an Account"
  description = "Identifies IPs from which users grant access to others on Azure resources and alerts on access granted from previously unrecognized IP addresses, helping to flag potential unauthorized access attempts."
  severity    = "medium"
  query       = query.activity_logs_detect_grant_permissions_detection

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}

query "activity_logs_detect_grant_permissions_detection" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Authorization/roleAssignments/write'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}
