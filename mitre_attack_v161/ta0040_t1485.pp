locals {
  mitre_attack_v161_ta0040_t1485_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_attack_technique_id = "T1485"
  })
}

benchmark "mitre_attack_v161_ta0040_t1485" {
  title         = "T1485 Data Destruction"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1485.md")
  children = [
    benchmark.mitre_attack_v161_ta0040_t1485_001,
    detection.network_application_gateway_deleted,
    detection.network_application_security_group_deleted,
    detection.automation_account_runbook_deleted,
    detection.container_registry_deleted,
    detection.compute_disk_deleted,
    detection.network_dns_zone_deleted,
    detection.event_hub_namespace_deleted,
    detection.network_firewall_deleted,
    detection.network_firewall_policy_deleted,
    detection.network_firewall_rule_deleted,
    detection.key_vault_deleted,
    detection.kubernetes_cluster_deleted,
    detection.network_watcher_deleted,
    detection.resource_group_deleted,
    detection.compute_snapshot_deleted,
    detection.sql_database_deleted,
    detection.sql_server_deleted,
    detection.sql_database_tde_created_or_updated,
    detection.storage_account_deleted,
    detection.virtual_network_deleted,
    detection.network_vpn_connection_deleted,
  ]

  tags = local.mitre_attack_v161_ta0040_t1485_common_tags
}

benchmark "mitre_attack_v161_ta0040_t1485_001" {
  title         = "T1485.001 Data Destruction: Lifecycle-Triggered Deletion"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1485_001.md")
  children = [
    detection.storage_account_lifecycle_policy_updated,
  ]
}