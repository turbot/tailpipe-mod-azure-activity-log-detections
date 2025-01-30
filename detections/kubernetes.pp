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
    detection.kubernetes_cluster_deleted,
  ]

  tags = merge(local.kubernetes_common_tags, {
    type = "Benchmark"
  })
}

detection "kubernetes_cluster_deleted" {
  title           = "Kubernetes Cluster Deleted"
  description     = "Detect when an Azure Kubernetes Cluster was deleted, which may lead to operational disruptions, loss of workloads, and reduced application availability."
  documentation   = file("./detections/docs/kubernetes_cluster_deleted.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.kubernetes_cluster_deleted

  tags = merge(local.kubernetes_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "kubernetes_cluster_deleted" {
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
