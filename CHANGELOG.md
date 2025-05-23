## v0.3.0 [2025-03-03]

_Enhancements_

- Added `title`, `description`, and `folder = "Subscription"` tag to `Activity Dashboard` queries for improved organization and clarity. ([#7](https://github.com/turbot/tailpipe-mod-azure-activity-log-detections/pull/7))
- Added `folder = "<service>"` tag to `service common tag locals` for better query categorization. ([#7](https://github.com/turbot/tailpipe-mod-azure-activity-log-detections/pull/7))
- Standardized all queries to use `service common tags`, ensuring consistency across detection queries. ([#7](https://github.com/turbot/tailpipe-mod-azure-activity-log-detections/pull/7))

## v0.2.0 [2025-02-06]

_Enhancements_

- Added documentation for `activity_dashboard` dashboard. ([#5](https://github.com/turbot/tailpipe-mod-azure-activity-log-detections/pull/5))

## v0.1.1 [2025-01-30]

_Bug fixes_

- Fix mod color scheme.

## v0.1.0 [2025-01-30]

_What's new?_

- New benchmarks added:
  - Activity Log Detections benchmark (`powerpipe benchmark run azure_activity_log_detections.benchmark.activity_log_detections`).
  - MITRE ATT&CK v16.1 benchmark (`powerpipe benchmark run azure_activity_log_detections.benchmark.mitre_attack_v161`).

- New dashboards added:
  - [Activity Log Activity Dashboard](https://hub.powerpipe.io/mods/turbot/azure_activity_log_detections/dashboards/dashboard.activity_dashboard)
