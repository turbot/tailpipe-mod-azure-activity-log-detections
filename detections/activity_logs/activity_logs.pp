locals {
  activity_log_detection_common_tags = merge(local.azure_detections_common_tags, {
    service = "Azure/ActivityLog"
  })
}

benchmark "activity_log" {
  title       = "Activity Log Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Activity logs."
  type        = "detection"
  children = [
    benchmark.activity_logs_automation_detections,
    benchmark.activity_logs_compute_detections,
    benchmark.activity_logs_container_registry_detections,
    benchmark.activity_logs_event_hub_detections,
    benchmark.activity_logs_frontdoor_detections,
    benchmark.activity_logs_iam_detections,
    benchmark.activity_logs_keyvault_detections,
    benchmark.activity_logs_kubernetes_detections,
    benchmark.activity_logs_monitor_detections,
    benchmark.activity_logs_network_detections,
    benchmark.activity_logs_resource_group_detections,
    benchmark.activity_logs_sql_detections,
    benchmark.activity_logs_storage_detections
  ]

  tags = merge(local.azure_activity_log_detections_common_tags, {
    type = "Benchmark"
  })
}
