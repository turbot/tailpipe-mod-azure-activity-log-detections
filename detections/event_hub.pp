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
    detection.event_hub_namespace_rule_authorized,
    detection.event_hub_namespace_deleted,
  ]

  tags = merge(local.event_hub_registry_common_tags, {
    type = "Benchmark"
  })
}

detection "event_hub_namespace_rule_authorized" {
  title           = "Event Hub Namespace Rule Authorized"
  description     = "Detect when an Azure Event Hub namespace authorization rule was created/updated, providing visibility into significant changes that may impact security, such as unauthorized access or privilege escalation."
  documentation   = file("./detections/docs/event_hub_namespace_rule_authorized.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.event_hub_namespace_rule_authorized

  tags = merge(local.event_hub_registry_common_tags, {
    mitre_attack_ids = "TA0003:T1078.001"
  })
}

detection "event_hub_namespace_deleted" {
  title           = "Event Hub Namespace Deleted"
  description     = "Detect when an Azure Event Hub namespace was deleted, providing visibility into significant changes that may impact security, operational workflows, or data availability."
  documentation   = file("./detections/docs/event_hub_namespace_deleted.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.event_hub_namespace_deleted

  tags = merge(local.event_hub_registry_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "event_hub_namespace_rule_authorized" {
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

query "event_hub_namespace_deleted" {
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