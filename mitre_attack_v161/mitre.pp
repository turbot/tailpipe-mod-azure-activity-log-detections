locals {
  mitre_attack_v161_common_tags = merge(local.azure_activity_log_detections_common_tags, {
    mitre_attack_version = "v16.1"
  })
}

benchmark "mitre_attack_v161" {
  title         = "MITRE ATT&CK v16.1"
  description   = "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations."
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/mitre.md")
  children = [
    benchmark.mitre_attack_v161_ta0003,
    benchmark.mitre_attack_v161_ta0005,
    benchmark.mitre_attack_v161_ta0006,
    benchmark.mitre_attack_v161_ta0040,
  ]

  tags = merge(local.mitre_attack_v161_common_tags, {
    type = "Benchmark"
  })
}
