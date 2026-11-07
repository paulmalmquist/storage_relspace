# ---------------------------------------------------------------------------------------------
# API: internal ingress, Cloud Run IAM in front, app-level OIDC verification behind it.
# Callers send the same Google ID token in X-Serverless-Authorization (Cloud Run IAM) and
# Authorization (Strongbox); the Go SDK does this with client.WithServerlessAuth().
# ---------------------------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "api" {
  name             = "${var.name}-api"
  location         = var.region
  ingress          = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  custom_audiences = [var.api_audience]

  template {
    service_account                  = google_service_account.api.email
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    max_instance_request_concurrency = var.api_concurrency
    timeout                          = "300s"

    scaling {
      min_instance_count = var.api_min_instances
      max_instance_count = var.api_max_instances
    }

    vpc_access {
      egress = "ALL_TRAFFIC"
      network_interfaces {
        network    = var.network_id
        subnetwork = var.subnetwork_id
      }
    }

    containers {
      name       = "api"
      image      = var.api_image
      args       = ["serve", "-addr", ":8080"]
      depends_on = ["cloud-sql-proxy"]

      ports {
        container_port = 8080
      }

      dynamic "env" {
        for_each = local.common_env
        content {
          name  = env.key
          value = env.value
        }
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
        # The outbox/maintenance worker runs inside serve, so CPU must stay allocated between
        # requests. Every instance competes for jobs with SKIP LOCKED leases.
        cpu_idle = false
      }

      startup_probe {
        http_get {
          path = "/readyz"
        }
        period_seconds    = 5
        failure_threshold = 12
      }

      liveness_probe {
        http_get {
          path = "/healthz"
        }
      }
    }

    containers {
      name  = "cloud-sql-proxy"
      image = var.sql_proxy_image
      args = [
        "--private-ip",
        "--auto-iam-authn",
        "--port=5432",
        "--health-check",
        "--http-address=0.0.0.0",
        google_sql_database_instance.pg.connection_name,
      ]

      startup_probe {
        http_get {
          path = "/startup"
          port = 9090
        }
        period_seconds    = 2
        failure_threshold = 30
      }
    }
  }

  depends_on = [
    google_kms_crypto_key_iam_member.api_data_kek,
    google_storage_bucket_iam_member.api_objects,
    google_sql_user.api,
  ]

  lifecycle {
    precondition {
      condition     = local.db_connections_needed <= var.db_max_connections
      error_message = "api_max_instances * db_pool_size + 10 exceeds db_max_connections."
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "api_invokers" {
  for_each = toset(concat(var.api_invokers, ["serviceAccount:${google_service_account.mcp.email}"]))
  name     = google_cloud_run_v2_service.api.name
  location = var.region
  role     = "roles/run.invoker"
  member   = each.value
}

# Schema migrations run as a one-off job under their own identity, never on replica start. The
# job creates the roles and schema on first run and grants strongbox_runtime to the API login.
resource "google_cloud_run_v2_job" "migrate" {
  name       = "${var.name}-migrate"
  location   = var.region
  depends_on = [google_sql_user.migrate, google_sql_user.api, google_project_iam_member.migrate_sql]

  template {
    template {
      service_account = google_service_account.migrate.email

      vpc_access {
        egress = "ALL_TRAFFIC"
        network_interfaces {
          network    = var.network_id
          subnetwork = var.subnetwork_id
        }
      }

      containers {
        image = var.api_image
        args = [
          "init", "-wait", "120s", "-shutdown-url", "http://127.0.0.1:9091/quitquitquit",
          "-bootstrap-roles", "-runtime-login", local.api_db_user,
        ]

        dynamic "env" {
          for_each = merge(local.common_env, {
            STRONGBOX_MIGRATION_DATABASE_URL = "postgres://${local.migrate_db_user}@127.0.0.1:5432/strongbox?sslmode=disable"
          })
          content {
            name  = env.key
            value = env.value
          }
        }
      }

      containers {
        name  = "cloud-sql-proxy"
        image = var.sql_proxy_image
        args  = ["--private-ip", "--auto-iam-authn", "--port=5432", "--quitquitquit", google_sql_database_instance.pg.connection_name]
      }
    }
  }
}

# ---------------------------------------------------------------------------------------------
# MCP server: verifies each user's token itself (MCP authorization spec), then calls the API as
# its own service account with X-On-Behalf-Of. It has no KMS, bucket or database permissions.
# ---------------------------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "mcp" {
  count                = var.deploy_mcp ? 1 : 0
  name                 = "${var.name}-mcp"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  invoker_iam_disabled = true # token verification happens in the MCP server

  template {
    service_account       = google_service_account.mcp.email
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

    vpc_access {
      egress = "ALL_TRAFFIC"
      network_interfaces {
        network    = var.network_id
        subnetwork = var.subnetwork_id
      }
    }

    containers {
      image = var.api_image
      args  = ["mcp", "--transport", "streamable-http", "--addr", ":8080"]

      ports {
        container_port = 8080
      }

      env {
        name  = "STRONGBOX_MCP_API_URL"
        value = google_cloud_run_v2_service.api.uri
      }
      env {
        name  = "STRONGBOX_MCP_GOOGLE_AUDIENCE"
        value = var.api_audience
      }
      env {
        name  = "STRONGBOX_MCP_PUBLIC_URL"
        value = var.mcp_public_url
      }
      env {
        name  = "STRONGBOX_AUTH_MODE"
        value = "oidc"
      }
      env {
        name  = "STRONGBOX_DELEGATION_AUDIENCES"
        value = jsonencode([var.mcp_audience])
      }
    }
  }
}
