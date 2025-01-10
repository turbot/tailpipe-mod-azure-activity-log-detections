locals {
  activity_log_container_registry_detection_common_tags = merge(local.activity_log_detection_common_tags, {
    service = "Azure/ContainerRegistry"
  })
}

benchmark "activity_logs_container_registry_detections" {
  title       = "Container Registry Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Container Registry activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_container_registries_create_deletions,
  ]

  tags = merge(local.activity_log_container_registry_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "activity_logs_detect_container_registries_create_deletions" {
  title       = "Detect Container Registries Deletions"
  description = "Detects the deletion of a Container Registry, providing visibility into significant changes that may impact container management and deployment."
  severity    = "low"
  query       = query.activity_logs_detect_container_registries_create_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}


query "activity_logs_detect_container_registries_create_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.ContainerRegistry/registries/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}
