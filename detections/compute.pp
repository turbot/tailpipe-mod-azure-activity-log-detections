locals {
  compute_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/Compute"
  })
}

benchmark "compute_detections" {
  title       = "Compute Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Compute activity logs."
  type        = "detection"
  children = [
    detection.compute_disk_deleted,
    detection.compute_snapshot_deleted,
    detection.compute_vm_role_assignment_created_or_updated,
  ]

  tags = merge(local.compute_common_tags, {
    type = "Benchmark"
  })
}

detection "compute_vm_role_assignment_created_or_updated" {
  title           = "Compute VM Role Assignment Created or Updated"
  description     = "Detect when a role assignment was created or updated for an Azure Virtual Machine, which may impact security and access controls by granting or revoking permissions."
  documentation   = file("./detections/docs/compute_vm_role_assignment_created_or_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.compute_vm_role_assignment_created_or_updated

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

detection "compute_disk_deleted" {
  title           = "Compute Disk Deleted"
  description     = "Detect when an Azure Managed Disk was deleted, which may lead to data loss or operational disruptions, impacting business continuity or recovery efforts."
  documentation   = file("./detections/docs/compute_disk_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.compute_disk_deleted

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "compute_snapshot_deleted" {
  title           = "Compute Snapshot Deleted"
  description     = "Detect when an Azure Managed Disk Snapshot was deleted, which may indicate malicious activity or result in data loss, impacting recovery and backup processes."
  documentation   = file("./detections/docs/compute_snapshot_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.compute_snapshot_deleted

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "compute_vm_role_assignment_created_or_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Authorization/roleAssignments/write'
      and resource_type = 'Microsoft.Compute/virtualMachines'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_disk_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Compute/disks/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "compute_snapshot_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Compute/snapshots/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}