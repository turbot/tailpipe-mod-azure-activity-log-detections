locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  common_dimensions_activity_logs_sql = <<-EOQ
  timestamp as timestamp, -- TODO: Use epoch_ms(tp_timestamp) when available
  action as operation,
  __RESOURCE_SQL__ as resource,
  actor as actor,
  actor_ip as source_ip, -- TODO: Use tp_source_ip when available
  repo as repository,
  tp_id as source_id,
  EOQ
}

variable "database" {
  type        = connection.tailpipe
  description = "Tailpipe database connection string."
  default     = connection.tailpipe.default
}