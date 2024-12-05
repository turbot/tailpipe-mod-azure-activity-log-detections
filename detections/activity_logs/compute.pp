detection_benchmark "activity_logs_compute_detections" {
  title = "Activity Log Compute Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Compute activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_virtual_machine_command_execution
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/Compute"
  })
}

detection "activity_logs_detect_virtual_machine_command_execution" {
  title       = "Detect Virtual Machine Command Execution"
  description = "Detects the command execution virtual machine"
  severity    = "medium"
  query       = query.activity_logs_detect_virtual_machine_command_execution

  references = [
    "https://adsecurity.org/?p=4277",
    "https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a",
    "https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#virtual-machine-contributor",
  ]

  tags = local.activity_log_detection_common_tags
}

query "activity_logs_detect_virtual_machine_command_execution" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Compute/virtualMachines/runCommand/action'
      and status = 'Succeeded'
    order by
      timestamp desc;
  EOQ
}
