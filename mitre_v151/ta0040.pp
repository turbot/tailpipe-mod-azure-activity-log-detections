locals {
  mitre_v151_ta0040_common_tags = merge(local.mitre_v151_common_tags, {
    mitre_tactic_id = "TA0040"
  })
}

benchmark "mitre_v151_ta0040" {
  title         = "TA0040 Impact"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040.md")
  children = [
    benchmark.mitre_v151_ta0040_t1485,
    benchmark.mitre_v151_ta0040_t1565,
  ]

  tags = merge(local.mitre_v151_ta0040_common_tags, {
    type = "Benchmark"
  })
}

