locals {
  container_registry_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/ContainerRegistry"
  })
}

benchmark "container_registry_detections" {
  title       = "Container Registry Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Container Registry activity logs."
  type        = "detection"
  children = [
    detection.container_registry_deleted,
  ]

  tags = merge(local.container_registry_common_tags, {
    type = "Benchmark"
  })
}

detection "container_registry_deleted" {
  title           = "Container Registry Deleted"
  description     = "Detect when a container registry was deleted, providing visibility into significant changes that may impact container management, deployment, or operational workflows."
  documentation   = file("./detections/docs/container_registry_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.container_registry_deleted

  tags = merge(local.container_registry_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "container_registry_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.ContainerRegistry/registries/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
