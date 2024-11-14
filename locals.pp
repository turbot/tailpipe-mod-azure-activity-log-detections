// Benchmarks and controls for specific services should override the "service" tag
locals {
  azure_detections_common_tags = {
    category = "Detection"
    plugin   = "azure"
    service  = "Azure"
  }
}

locals {
    common_activity_logs_sql = <<-EOQ
    tp_timestamp as timestamp,
    operation_name as operation,
    resource_id as resource,
    caller as actor,
    tp_index::varchar as subscription_id,
    resource_group_name as resource_group,
    tp_id as source_id,
    status as event_status,
    *
    EOQ
}