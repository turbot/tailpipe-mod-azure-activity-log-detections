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
    detection.detect_compute_vm_role_assignment_changes,
    detection.detect_compute_disk_deletions,
    detection.detect_compute_snapshot_deletions,
  ]

  tags = merge(local.compute_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_compute_vm_role_assignment_changes" {
  title           = "Detect Compute VM Role Assignment Changes"
  description     = "Detect Azure Virtual Machines to check for role assignment changes, which may impact security and access controls."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_compute_vm_role_assignment_changes

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

detection "detect_compute_disk_deletions" {
  title           = "Detect Compute Disk Deletions"
  description     = "Detect Azure Managed Disks to check for deletions that may lead to data loss or operational impact."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_compute_disk_deletions

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "detect_compute_snapshot_deletions" {
  title           = "Detect Compute Snapshot Deletions"
  description     = "Detect Azure Managed Disk Snapshots to check for deletions that may indicate malicious activity or result in data loss."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_compute_snapshot_deletions

  tags = merge(local.compute_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "detect_compute_vm_role_assignment_changes" {
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

query "detect_compute_disk_deletions" {
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

query "detect_compute_snapshot_deletions" {
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