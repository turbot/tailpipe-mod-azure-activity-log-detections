dashboard "activity_dashboard" {

  title         = "Activity Log Activity Dashboard"
  documentation = file("./dashboards/docs/activity_dashboard.md")

  tags = {
    type    = "Dashboard"
    service = "Azure/ActivityLog"
  }

  container {
    # Single card to show total logs
    card {
      query = query.activity_dashboard_total_logs
      width = 2
    }
  }

  container {

    chart {
      title = "Logs by Subscription"
      query = query.activity_dashboard_logs_by_subscription
      type  = "column"
      width = 6
    }

    chart {
      title = "Logs by Resource Group"
      query = query.activity_dashboard_logs_by_resource_group
      type  = "column"
      width = 6
    }

    chart {
      title = "Top 10 Actors"
      query = query.activity_dashboard_logs_by_actor
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Source IPs"
      query = query.activity_dashboard_logs_by_source_ip
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Services"
      query = query.activity_dashboard_logs_by_service
      type  = "table"
      width = 6
    }

    chart {
      title = "Top 10 Events"
      query = query.activity_dashboard_logs_by_event
      type  = "table"
      width = 6
    }

  }
}

# -----------------------------
# Query Definitions
# -----------------------------

query "activity_dashboard_total_logs" {
  title = "Log Count"

  sql = <<-EOQ
    select
      count(*) as "Total Logs"
    from
      azure_activity_log;
  EOQ
}

query "activity_dashboard_logs_by_resource_group" {
  title = "Logs by Resource Group"

  sql = <<-EOQ
    select
      resource_group_name as "Resource Group",
      count(*) as "Logs"
    from
      azure_activity_log
    where
      resource_group_name is not null
    group by
      resource_group_name
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_subscription" {
  title = "Logs by Subscription"

  sql = <<-EOQ
    select
      subscription_id as "Subscription",
      count(*) as "Logs"
    from
      azure_activity_log
    where
      subscription_id is not null
    group by
      subscription_id
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_actor" {
  title = "Top 10 Actors"

  sql = <<-EOQ
    select
      caller as "Actor",
      count(*) as "Logs"
    from
      azure_activity_log
    where
      caller is not null
    group by
      caller
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_source_ip" {
  title = "Top 10 Source IPs"

  sql = <<-EOQ
    select
      tp_source_ip as "Source IP",
      count(*) as "Logs"
    from
      azure_activity_log
    where
      tp_source_ip is not null
    group by
      tp_source_ip
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_service" {
  title = "Top 10 Service"

  sql = <<-EOQ
    select
      resource_provider_name as "Service",
      count(*) as "Logs"
    from
      azure_activity_log
    where
      resource_provider_name is not null
    group by
      resource_provider_name
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_event" {
  title = "Top 10 Events"

  sql = <<-EOQ
    select
      operation_name as "Event",
      count(*) as "Logs"
    from
      azure_activity_log
    where
      operation_name is not null
    group by
      operation_name
    order by
      count(*) desc
    limit 10;
  EOQ
}
