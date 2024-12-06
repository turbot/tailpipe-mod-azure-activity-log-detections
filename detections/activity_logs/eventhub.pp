benchmark "activity_logs_event_hub_detections" {
  title = "Activity Log Event Hub Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Event Hub activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_event_hub_auth_rule_create_update,
    detection.activity_logs_detect_event_hub_delete,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/EventHub"
  })
}

detection "activity_logs_detect_event_hub_auth_rule_create_update" {
  title       = "Detect Event Hubs Auth Rule Created or Updated"
  description = "Detects when a Azure Event Hubs Auth Rule is created or updated."
  severity    = "medium"
  query       = query.activity_logs_detect_event_hub_auth_rule_create_update

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_event_hub_delete" {
  title       = "Detect Event Hubs Deleted"
  description = "Detects the deletion of Azure Event Hubs."
  severity    = "medium"
  query       = query.activity_logs_detect_event_hub_delete

  tags = local.activity_log_detection_common_tags
}

query "activity_logs_detect_event_hub_auth_rule_create_update" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.EventHub/namespaces/authorizationRules/write'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_event_hub_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.EventHub/namespaces/eventhubs/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}