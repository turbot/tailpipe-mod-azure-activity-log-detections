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
    detection.detect_container_registry_deletions,
  ]

  tags = merge(local.container_registry_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_container_registry_deletions" {
  title           = "Detect Container Registry Deletions"
  description     = "Detect the deletions of a Container Registry, providing visibility into significant changes that may impact container management and deployment."
  documentation   = file("./detections/docs/detect_container_registry_deletions.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_container_registry_deletions

  tags = merge(local.container_registry_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "detect_container_registry_deletions" {
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
