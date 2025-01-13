locals {
  mitre_v151_ta0040_t1485_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1485"
  })
}

benchmark "mitre_v151_ta0040_t1485" {
  title         = "T1485 Data Destruction"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1485.md")
  children = [
    benchmark.mitre_v151_ta0040_t1485_001,
    detection.activity_logs_detect_network_application_gateway_deletions,
    detection.activity_logs_detect_network_application_security_group_deletions,
    detection.activity_logs_detect_automation_runbook_deletions,
    detection.activity_logs_detect_container_registry_deletions,
    detection.activity_logs_detect_compute_disk_deletions,
    detection.activity_logs_detect_network_dns_zone_deletions,
    detection.activity_logs_detect_event_hub_deletions,
    detection.activity_logs_detect_network_firewall_deletions,
    detection.activity_logs_detect_network_firewall_policy_deletions,
    detection.activity_logs_detect_network_firewall_rule_deletions,
    detection.activity_logs_detect_frontdoor_firewall_policy_deletions,
    detection.activity_logs_detect_keyvault_secret_deletions,
    detection.activity_logs_detect_keyvault_vault_deletions,
    detection.activity_logs_detect_kubernetes_cluster_deletions,
    detection.activity_logs_detect_network_security_group_deletions,
    detection.activity_logs_detect_network_watcher_deletions,
    detection.activity_logs_detect_resource_group_deletions,
    detection.activity_logs_detect_compute_snapshot_deletions,
    detection.activity_logs_detect_sql_database_deletions,
    detection.activity_logs_detect_sql_server_deletions,
    detection.activity_logs_detect_sql_tde_updates,
    detection.activity_logs_detect_storage_account_deletions,
    detection.activity_logs_detect_virtual_network_deletions,
    detection.activity_logs_detect_network_vpn_connection_deletions,
  ]

  tags = local.mitre_v151_ta0040_t1485_common_tags
}

benchmark "mitre_v151_ta0040_t1485_001" {
  title         = "T1485.001 Data Destruction: Lifecycle-Triggered Deletion"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1485_001.md")
  children = [
    detection.activity_logs_detect_lifecycle_policy_updates,
  ]
}