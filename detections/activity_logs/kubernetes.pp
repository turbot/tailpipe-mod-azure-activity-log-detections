locals {
  activity_log_kubernetes_detection_common_tags = merge(local.activity_log_detection_common_tags, {
    service = "Azure/KubernetesService"
  })
}

benchmark "activity_logs_kubernetes_detections" {
  title       = "Kubernetes Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Kubernetes activity logs."
  type        = "detection"
  children = [
    detection.activity_logs_detect_kubernetes_clusters_deletions,
    detection.activity_logs_detect_kubernetes_pods_deletions,
  ]

  tags = merge(local.activity_log_detection_common_tags, {
    type    = "Benchmark"
  })
}

detection "activity_logs_detect_kubernetes_clusters_deletions" {
  title       = "Detect Kubernetes Clusters Deletions"
  description = "Detects when a Azure Kubernetes Cluster is created or deleted."
  severity    = "medium"
  query       = query.activity_logs_detect_kubernetes_clusters_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "activity_logs_detect_kubernetes_pods_deletions" {
  title       = "Detect Kubernetes Pods Deletions"
  description = "Detects the deletion of Azure Kubernetes Pods."
  severity    = "medium"
  query       = query.activity_logs_detect_kubernetes_pods_deletions

  tags = merge(local.activity_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "activity_logs_detect_kubernetes_clusters_deletions" {
  sql = <<-EOQ
    select
      ${local.common_activity_logs_sql}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Kubernetes/connectedClusters/delete'
      ${local.activity_logs_detection_where_conditions}
    order by
      timestamp desc;
  EOQ
}

query "activity_logs_detect_kubernetes_pods_deletions" {
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