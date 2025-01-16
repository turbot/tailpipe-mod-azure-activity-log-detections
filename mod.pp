mod "azure_activity_log_detections" {
  # hub metadata
  title         = "Azure Activity Log Detections"
  description   = "Search your Azure activity logs for high risk actions using Tailpipe."
  color         = "#191717"
  #documentation = file("./docs/index.md")
  #icon          = "/images/mods/turbot/azure.svg"
  categories    = ["azure", "dashboard", "detections", "public cloud"]
  database      = var.database

  opengraph {
    title       = "Tailpipe Mod for Azure Activity Log Detections"
    description = "Search your Azure activity logs for high risk actions using Tailpipe."
    #image       = "/images/mods/turbot/azure-social-graphic.png"
  }
}
