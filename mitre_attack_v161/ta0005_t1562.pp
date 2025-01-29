locals {
  mitre_attack_v161_ta0005_t1562_common_tags = merge(local.mitre_attack_v161_ta0005_common_tags, {
    mitre_attack_technique_id = "T1562"
  })
}

benchmark "mitre_attack_v161_ta0005_t1562" {
  title         = "T1562 Impair Defenses"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562.md")
  children = [
    benchmark.mitre_attack_v161_ta0005_t1562_001,
    benchmark.mitre_attack_v161_ta0005_t1562_002,
    benchmark.mitre_attack_v161_ta0005_t1562_007,
  ]

  tags = local.mitre_attack_v161_ta0005_t1562_common_tags
}

benchmark "mitre_attack_v161_ta0005_t1562_001" {
  title         = "T1562.001 Impair Defenses: Disable or Modify Tools"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562_001.md")
  children = [
    detection.storage_account_lifecycle_policy_updated,
  ]
}

benchmark "mitre_attack_v161_ta0005_t1562_002" {
  title         = "T1562.002 Impair Defenses: Disable Windows Event Logging"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562_002.md")
  children = [
    detection.monitor_diagnostic_setting_deleted,
  ]
}

benchmark "mitre_attack_v161_ta0005_t1562_007" {
  title         = "T1562.007 Impair Defenses: Disable or Modify Cloud Firewall"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562_007.md")
  children = [
    detection.front_door_firewall_policy_deleted,
    detection.network_firewall_rule_created_or_updated,
    detection.network_security_group_created_or_updated,
    detection.network_security_group_deleted,
    detection.network_vpn_connection_created_or_updated,
    detection.sql_server_firewall_rule_created_or_updated,
    detection.network_virtual_network_created_or_updated,
  ]
}
