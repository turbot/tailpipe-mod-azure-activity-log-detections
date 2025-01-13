// Benchmarks and controls for specific services should override the "service" tag
locals {
  azure_activity_log_detections_common_tags = {
    category = "Detections"
    plugin   = "azure"
    service  = "Azure/ActivityLog"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_sql_columns = <<-EOQ
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

  // Keep same order as SQL statement for easier readability
  detection_display_columns = [
    "timestamp",
    "operation",
    "resource",
    "actor",
    "subscription_id",
    "resource_group",
    "source_id",
    "event_status",
  ]

  detection_sql_where_conditions = <<-EOQ
    and status = 'Succeeded'
  EOQ
}