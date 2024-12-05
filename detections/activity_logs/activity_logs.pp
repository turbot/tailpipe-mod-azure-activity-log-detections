locals {
  activity_log_detection_common_tags = {
    service  = "Azure/Monitor"
  }
}

detection_benchmark "activity_logs" {
  title = "Activity Log Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Activity logs."
  type = "detection"
  children = [
    detection_benchmark.activity_logs_automation_detections,
    detection_benchmark.activity_logs_compute_detections,
    detection_benchmark.activity_logs_container_registry_detections,
    detection_benchmark.activity_logs_event_hub_detections,
    detection_benchmark.activity_logs_frontdoor_detections,
    detection_benchmark.activity_logs_iam_detections,
    detection_benchmark.activity_logs_keyvault_detections,
    detection_benchmark.activity_logs_kubernetes_detections,
    detection_benchmark.activity_logs_monitor_detections,
    detection_benchmark.activity_logs_network_detections,
    detection_benchmark.activity_logs_resource_group_detections,
    detection_benchmark.activity_logs_storage_detections
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type = "Benchmark"
  })
}
