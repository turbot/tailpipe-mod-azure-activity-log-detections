benchmark "activity_logs_compute_detections" {
  title       = "Compute Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Compute activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_compute_vm_role_assignment_changes,
    detection.activity_logs_detect_compute_disk_deletions,
    detection.activity_logs_detect_compute_snapshot_deletions,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/Compute"
  })
}

detection "activity_logs_detect_compute_vm_role_assignment_changes" {
  title       = "Detect Compute VM Role Assignment Changes"
  description = "Detect Azure Virtual Machines to check for role assignment changes, which may impact security and access controls."
  severity    = "medium"
  query       = query.activity_logs_detect_compute_vm_role_assignment_changes

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0003:T1078.004"
  })
}

detection "activity_logs_detect_compute_disk_deletions" {
  title       = "Detect Compute Disk Deletions"
  description = "Detect Azure Managed Disks to check for deletions that may lead to data loss or operational impact."
  severity    = "high"
  query       = query.activity_logs_detect_compute_disk_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "activity_logs_detect_compute_snapshot_deletions" {
  title       = "Detect Compute Snapshot Deletions"
  description = "Detect Azure Managed Disk Snapshots to check for deletions that may indicate malicious activity or result in data loss."
  severity    = "high"
  query       = query.activity_logs_detect_compute_snapshot_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "activity_logs_detect_compute_vm_role_assignment_changes" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Authorization/roleAssignments/write'
      and resource_type = 'Microsoft.Compute/virtualMachines'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_compute_disk_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Compute/disks/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_compute_snapshot_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Compute/snapshots/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}