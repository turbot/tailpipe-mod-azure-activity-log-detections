dashboard "activity_dashboard" {
  title = "Activity Log Activity Dashboard"

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
      title = "Logs by Level"
      query = query.activity_dashboard_logs_by_level
      type  = "column"
      width = 6
    }

    chart {
      title = "Logs by Category"
      query = query.activity_dashboard_logs_by_category
      type  = "column"
      width = 6
    }

    chart {
      title = "Logs by Operation"
      query = query.activity_dashboard_logs_by_operation
      type  = "column"
      width = 6
    }

    chart {
      title = "Top 10 Callers"
      query = query.activity_dashboard_logs_by_caller
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
      title = "Top 10 Resources"
      query = query.activity_dashboard_logs_by_resource
      type  = "table"
      width = 6
    }

  }
}

# -----------------------------
# Query Definitions
# -----------------------------

query "activity_dashboard_total_logs" {
  title = "Total Log Count"

  sql = <<-EOQ
    select
      count(*) as "total logs"
    from
      azure_activity_log;
  EOQ
}

query "activity_dashboard_logs_by_level" {
  title = "Logs by Level"

  sql = <<-EOQ
    select
      level as "level",
      count(*) as "logs"
    from
      azure_activity_log
    where
      level is not null
    group by
      level
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_category" {
  title = "Logs by Category"

  sql = <<-EOQ
    select
      category as "category",
      count(*) as "logs"
    from
      azure_activity_log
    where
      category is not null
    group by
      category
    order by
      count(*) desc
    limit 10;
  EOQ
}

query "activity_dashboard_logs_by_operation" {
  title = "Logs by Operation"

  sql = <<-EOQ
    select
      operation_name as "operation name",
      count(*) as "logs"
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

query "activity_dashboard_logs_by_caller" {
  title = "Top 10 Callers"

  sql = <<-EOQ
    select
      caller as "caller",
      count(*) as "logs"
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
      tp_source_ip as "source ip",
      count(*) as "logs"
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

query "activity_dashboard_logs_by_resource" {
  title = "Top 10 Resources"

  sql = <<-EOQ
    select
      resource_id as "resource",
      count(*) as "logs"
    from
      azure_activity_log
    where
      resource_id is not null
    group by
      resource_id
    order by
      count(*) desc
    limit 10;
  EOQ
}