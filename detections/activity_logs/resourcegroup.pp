detection_benchmark "activity_logs_resource_group_detections" {
  title = "Activity Log Resource Group Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Resource Group activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_resource_group_delete
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/ResourceGroup"
  })
}

detection "activity_logs_detect_resource_group_delete" {
  title       = "Detect Resource Group Deleted"
  description = "Detects the deletion of Azure Resource Group."
  severity    = "low"
  query       = query.activity_logs_detect_resource_group_delete

  references = [
    "https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal"
  ]

  tags = local.activity_log_detection_common_tags
}

query "activity_logs_detect_resource_group_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Resources/subscriptions/resourcegroups/delete'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}
