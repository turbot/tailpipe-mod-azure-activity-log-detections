locals {
  kubernetes_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    service = "Azure/KubernetesService"
  })
}

benchmark "kubernetes_detections" {
  title       = "Kubernetes Detections"
  description = "This detection benchmark contains recommendations when scanning Azure Kubernetes activity logs."
  type        = "detection"
  children = [
    detection.detect_kubernetes_cluster_deletions
  ]

  tags = merge(local.kubernetes_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_kubernetes_cluster_deletions" {
  title           = "Detect Kubernetes Cluster Deletions"
  description     = "Detects when a Azure Kubernetes Cluster is created or deleted."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_kubernetes_cluster_deletions

  tags = merge(local.kubernetes_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "detect_kubernetes_cluster_deletions" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      azure_activity_log
    where
      operation_name = 'Microsoft.Kubernetes/connectedClusters/delete'
      ${local.detection_sql_where_conditions}
    order by
      timestamp desc;
  EOQ
}
