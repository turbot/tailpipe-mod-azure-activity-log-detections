locals {
  mitre_v151_ta0005_t1562_common_tags = merge(local.mitre_v151_ta0002_common_tags, {
    mitre_technique_id = "T1562"
  })
}

benchmark "mitre_v151_ta0005_t1562" {
  title         = "T1562 Impair Defenses"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0005_t1562.md")
  children = [
    benchmark.mitre_v151_ta0005_t1562_007,
  ]

  tags = local.mitre_v151_ta0005_t1562_common_tags
}

benchmark "mitre_v151_ta0005_t1562_007" {
  title         = "T1562.007 Impair Defenses: Disable or Modify Cloud Firewall"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0005_t1562_007.md")
  children = [
    detection.activity_logs_detect_firewall_policy_updates,
    detection.activity_logs_detect_firewall_rule_updates,
    detection.activity_logs_detect_firewall_updates,
    detection.activity_logs_detect_network_security_group_updates,
    detection.activity_logs_detect_sql_firewall_rule_modifications,
    detection.activity_logs_detect_virtual_networks_modified,
    detection.activity_logs_detect_vpn_connection_updates,
  ]
}