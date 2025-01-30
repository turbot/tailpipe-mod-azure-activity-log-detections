benchmark "activity_log_detections" {
  title       = "Activity Log Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Activity logs."
  type        = "detection"
  children = [
    benchmark.automation_detections,
    benchmark.compute_detections,
    benchmark.container_registry_detections,
    benchmark.event_hub_detections,
    benchmark.front_door_detections,
    benchmark.iam_detections,
    benchmark.key_vault_detections,
    benchmark.kubernetes_detections,
    benchmark.monitor_detections,
    benchmark.network_detections,
    benchmark.resource_group_detections,
    benchmark.sql_detections,
    benchmark.storage_detections
  ]

  tags = merge(local.azure_activity_log_detections_common_tags, {
    type = "Benchmark"
  })
}
