benchmark "activity_logs_kubernetes_detections" {
  title = "Activity Log Kubernetes Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Kubernetes activity logs."
  type = "detection"
  children = [
    detection.activity_logs_detect_kubernetes_clusters_create_delete,
    detection.activity_logs_detect_kubernetes_pods_delete,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
    service = "Azure/KubernetesService"
  })
}

detection "activity_logs_detect_kubernetes_clusters_create_delete" {
  title       = "Detect Kubernetes Clusters Created or Deleted"
  description = "Detects when a Azure Kubernetes Cluster is created or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_kubernetes_clusters_create_delete

  tags = local.activity_log_detection_common_tags
}

detection "activity_logs_detect_kubernetes_pods_delete" {
  title       = "Detect Kubernetes Pods Deleted"
  description = "Detects the deletion of Azure Kubernetes Pods."
  severity    = "medium"
  query       = query.activity_logs_detect_kubernetes_pods_delete

  tags = local.activity_log_detection_common_tags
}

query "activity_logs_detect_kubernetes_clusters_create_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name in (
        'Microsoft.Kubernetes/connectedClusters/write',
        'Microsoft.Kubernetes/connectedClusters/delete'
      )
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_kubernetes_pods_delete" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Kubernetes/connectedClusters/pods/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}