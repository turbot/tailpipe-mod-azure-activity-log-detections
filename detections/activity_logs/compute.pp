# benchmark "activity_logs_compute_detections" {
#   title = "Compute Detections"
#   description = "This detection benchmark contains recommendations when scanning Azure Compute activity logs."
#   type = "detection"
#   children = [
#     detection.activity_logs_detect_virtual_machine_command_execution
#   ]

#   tags = merge(local.activity_log_detection_common_tags, {
#     type    = "Benchmark"
#     service = "Azure/Compute"
#   })
# }

# detection "activity_logs_detect_virtual_machine_command_execution" {
#   title       = "Detect Virtual Machine Command Execution"
#   description = "Detects the command execution virtual machine"
#   severity    = "medium"
#   query       = query.activity_logs_detect_virtual_machine_command_execution

#   tags = merge(local.activity_log_detection_common_tags, {
# mitre_attack_ids = ""
# })
# }

# query "activity_logs_detect_virtual_machine_command_execution" {
#   sql = <<-EOQ
#     select
#       ${local.common_activity_logs_sql}
#     from
#       azure_activity_log
#     where
#       operation_name = 'Microsoft.Compute/virtualMachines/runCommand/action'
#       ${local.activity_logs_detection_where_conditions}
#     order by
#       timestamp desc;
#   EOQ
# }

## These logs appear when Running a custom script to install software on a VM or to run a script on a VM