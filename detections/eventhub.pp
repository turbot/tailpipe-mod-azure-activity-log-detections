locals {
  event_hub_registry_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/EventHub"
  })
}

benchmark "event_hub_detections" {
  title       = "Event Hub Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Event Hub activity logs."
  type        = "detection"
  children = [
    detection.detect_event_hub_auth_rule_updates,
    detection.detect_event_hub_deletions,
  ]

  tags = merge(local.event_hub_registry_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_event_hub_auth_rule_updates" {
  title           = "Detect Event Hub Auth Rule Updates"
  description     = "Detect when a Azure Event HubsAuth Rules are updated, providing visibility into significant changes that may impact security."
  documentation   = file("./detections/docs/detect_event_hub_auth_rule_updates.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_event_hub_auth_rule_updates

  tags = merge(local.event_hub_registry_common_tags, {
    mitre_attack_ids = "TA0003:T1078.001"
  })
}

detection "detect_event_hub_deletions" {
  title           = "Detect Event Hub Deletions"
  description     = "Detect the deletions of Azure Event Hub, providing visibility into significant changes that may impact security."
  documentation   = file("./detections/docs/detect_event_hub_deletions.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_event_hub_deletions

  tags = merge(local.event_hub_registry_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "detect_event_hub_auth_rule_updates" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.EventHub/namespaces/authorizationRules/write'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "detect_event_hub_deletions" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.EventHub/namespaces/eventhubs/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}