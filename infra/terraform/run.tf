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
    service_account       = google_service_account.api.email
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

    scaling {
      min_instance_count = 1
      max_instance_count = 10
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
      args       = ["serve", "--addr", ":8080"]
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
}

resource "google_cloud_run_v2_service_iam_member" "api_invokers" {
  for_each = toset(concat(var.api_invokers, ["serviceAccount:${google_service_account.mcp.email}"]))
  name     = google_cloud_run_v2_service.api.name
  location = var.region
  role     = "roles/run.invoker"
  member   = each.value
}

# Schema migrations run as a one-off job, not on every replica start.
resource "google_cloud_run_v2_job" "migrate" {
  name     = "${var.name}-migrate"
  location = var.region

  template {
    template {
      service_account = google_service_account.api.email

      vpc_access {
        egress = "ALL_TRAFFIC"
        network_interfaces {
          network    = var.network_id
          subnetwork = var.subnetwork_id
        }
      }

      containers {
        image = var.api_image
        args  = ["init", "--wait", "120s", "--shutdown-url", "http://127.0.0.1:9091/quitquitquit"]

        dynamic "env" {
          for_each = local.common_env
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
