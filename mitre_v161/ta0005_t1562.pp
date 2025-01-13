locals {
  mitre_v161_ta0005_t1562_common_tags = merge(local.mitre_v161_ta0005_common_tags, {
    mitre_technique_id = "T1562"
  })
}

benchmark "mitre_v161_ta0005_t1562" {
  title         = "T1562 Impair Defenses"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0005_t1562.md")
  children = [
    benchmark.mitre_v161_ta0005_t1562_007,
  ]

  tags = local.mitre_v161_ta0005_t1562_common_tags
}

benchmark "mitre_v161_ta0005_t1562_007" {
  title         = "T1562.007 Impair Defenses: Disable or Modify Cloud Firewall"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0005_t1562_007.md")
  children = [
    detection.detect_network_firewall_policy_updates,
    detection.detect_network_firewall_rule_updates,
    detection.detect_network_firewall_updates,
    detection.detect_network_security_group_updates,
    detection.detect_sql_firewall_rule_updates,
    detection.detect_virtual_network_updates,
    detection.detect_vpn_connection_updates,
  ]
}