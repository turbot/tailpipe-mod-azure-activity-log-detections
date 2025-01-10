locals {
  activity_log_event_hub_registry_detection_common_tags = merge(local.activity_log_detection_common_tags, {
    service = "Azure/EventHub"
  })
}

benchmark "activity_logs_event_hub_detections" {
  title       = "Event Hub Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Event Hub activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_event_hub_auth_rule_creations,
    detection.activity_logs_detect_event_hub_deletions,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type = "Benchmark"
  })
}

detection "activity_logs_detect_event_hub_auth_rule_creations" {
  title       = "Detect Event Hubs Auth Rule Creations"
  description = "Detects when a Azure Event Hubs Auth Rule is created, providing visibility into significant changes that may impact security."
  severity    = "medium"
  query       = query.activity_logs_detect_event_hub_auth_rule_creations

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_event_hub_deletions" {
  title       = "Detect Event Hubs Deletions"
  description = "Detects the deletion of Azure Event Hubs, providing visibility into significant changes that may impact security."
  severity    = "medium"
  query       = query.activity_logs_detect_event_hub_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "activity_logs_detect_event_hub_auth_rule_creations" {
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

query "activity_logs_detect_event_hub_deletions" {
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