locals {
  resource_group_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/ResourceGroup"
  })
}

benchmark "resource_group_detections" {
  title       = "Resource Group Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Resource Group activity logs."
  type        = "detection"
  children = [
    detection.resource_group_deleted,
  ]

  tags = merge(local.resource_group_common_tags, {
    type = "Benchmark"
  })
}

detection "resource_group_deleted" {
  title           = "Resource Group Deleted"
  description     = "Detect when an Azure Resource Group was deleted, potentially impacting associated resources, disrupting operations, and leading to loss of critical configurations or data."
  documentation   = file("./detections/docs/resource_group_deleted.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.resource_group_deleted

  tags = merge(local.resource_group_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "resource_group_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Resources/subscriptions/resourcegroups/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
