mod "azure_activity_log_detections" {
  # hub metadata
  title         = "Azure Activity Log Detections"
  description   = "Run detections and view dashboards for your Azure activity logs to monitor and analyze activity across your Azure subscriptions using Powerpipe and Tailpipe."
  color         = "#0089D6"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/azure-activity-log-detections.svg"
  categories    = ["azure", "dashboard", "detections", "public cloud"]
  database      = var.database

  opengraph {
    title       = "Powerpipe Mod for Azure Activity Log Detections"
    description = "Run detections and view dashboards for your Azure activity logs to monitor and analyze activity across your Azure subscriptions using Powerpipe and Tailpipe."
    image       = "/images/mods/turbot/azure-activity-log-detections-social-graphic.png"
  }
}
