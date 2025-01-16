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
    detection.detect_resource_group_deletions
  ]

  tags = merge(local.resource_group_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_resource_group_deletions" {
  title           = "Detect Resource Group Deletions"
  description     = "Detects the deletion of Azure Resource Group, providing visibility into significant changes that may impact resources."
  documentation   = file("./detections/docs/detect_resource_group_deletions.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_resource_group_deletions

  tags = merge(local.resource_group_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "detect_resource_group_deletions" {
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
