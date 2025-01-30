# Azure Activity Log Detections Mod

[Tailpipe](https://tailpipe.io) is an open-source CLI tool that allows you to collect logs and query them with SQL.

[Azure](https://azure.microsoft.com) provides on-demand cloud computing platforms and APIs to authenticated customers on a metered pay-as-you-go basis.

The [Azure Activity Log Detections Mod](https://hub.powerpipe.mods/turbot/tailpipe-mod-azure-activity-log-detections) contains pre-built dashboards and detections, which can be used to monitor and analyze activity across your Azure accounts.

<img src="https://raw.githubusercontent.com/turbot/tailpipe-mod-azure-activity-log-detections/main/docs/images/azure_activity_log_mitre_dashboard.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/tailpipe-mod-azure-activity-log-detections/main/docs/images/azure_activity_log_activity_dashboard.png" width="50%" type="thumbnail"/>

## Documentation

- **[Dashboards →](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-azure-activity-log-detections/dashboards)**
- **[Benchmarks and detections →](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-azure-activity-log-detections/benchmarks)**

## Getting Started

Install Powerpipe from the [downloads](https://powerpipe.io/downloads) page:

```sh
# MacOS
brew install turbot/tap/powerpipe
```

```sh
# Linux or Windows (WSL)
sudo /bin/sh -c "$(curl -fsSL https://powerpipe.io/install/powerpipe.sh)"
```

This mod also requires Azure activity logs to be collected using [Tailpipe](https://tailpipe.io) with the [Azure plugin](https://hub.tailpipe.io/plugins/turbot/azure):
- [Get started with the Azure plugin for Tailpipe →](https://hub.tailpipe.io/plugins/turbot/azure#getting-started)

Install the mod:

```sh
mkdir dashboards
cd dashboards
powerpipe mod install github.com/turbot/tailpipe-mod-azure-activity-log-detections
```

### Browsing Dashboards

Start the dashboard server:

```sh
powerpipe server
```

Browse and view your dashboards at **http://localhost:9033**.

### Running Benchmarks in Your Terminal

Instead of running benchmarks in a dashboard, you can also run them within your
terminal with the `powerpipe benchmark` command:

List available benchmarks:

```sh
powerpipe benchmark list
```

Run a benchmark:

```sh
powerpipe benchmark run azure_activity_log_detections.benchmark.mitre_attack_v161
```

Different output formats are also available, for more information please see
[Output Formats](https://powerpipe.io/docs/reference/cli/benchmark#output-formats).
