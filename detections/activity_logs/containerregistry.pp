detection_benchmark "activity_logs_container_registry_detections" {
  title = "Activity Log Container Registry Detections"
  description = "This detection benchmark contains recommendations when scanning Azure  Container Registry activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_container_registries_create_delete,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/ContainerRegistry"
  })
}

detection "activity_logs_detect_container_registries_create_delete" {
  title       = "Detect Container Registries Created or Deleted"
  description = "Detects the creation or deletion of a Container Registry, providing visibility into significant changes that may impact container management and deployment."
  severity    = "low"
  query       = query.activity_logs_detect_container_registries_create_delete

  references = [
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations",
  ]

  tags = local.activity_log_detection_common_tags
}


query "activity_logs_detect_container_registries_create_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.ContainerRegistry/registries/write',
        'Microsoft.ContainerRegistry/registries/delete'
      )
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
