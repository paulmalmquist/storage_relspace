locals {
  # Cloud SQL IAM database users are the service account email without ".gserviceaccount.com".
  api_db_user     = trimsuffix(google_service_account.api.email, ".gserviceaccount.com")
  migrate_db_user = trimsuffix(google_service_account.migrate.email, ".gserviceaccount.com")

  # Connections at full scale-out, plus 10 for migrations, admin commands and the proxy.
  db_connections_needed = var.api_max_instances * var.db_pool_size + 10

  common_env = {
    STRONGBOX_ENV                  = "production"
    STRONGBOX_AUTH_MODE            = "oidc"
    STRONGBOX_KMS_BACKEND          = "gcp"
    STRONGBOX_KMS_KEY_NAME         = google_kms_crypto_key.data_kek.id
    STRONGBOX_BLOB_BACKEND         = "gcs"
    STRONGBOX_GCS_BUCKET           = google_storage_bucket.blobs.name
    STRONGBOX_DATABASE_URL         = "postgres://${local.api_db_user}@127.0.0.1:5432/strongbox?sslmode=disable"
    STRONGBOX_APP_ENV              = var.app_env
    STRONGBOX_DB_MAX_CONNS         = tostring(var.db_pool_size)
    STRONGBOX_JWT_AUDIENCES        = jsonencode([var.api_audience])
    STRONGBOX_DELEGATION_AUDIENCES = jsonencode([var.api_audience, var.mcp_audience])
    STRONGBOX_REQUIRE_FIPS         = "true"
    STRONGBOX_EXPOSE_DOCS          = "false"
    STRONGBOX_METRICS_EXPORTER     = "gcp"
    # Cloud Run caps HTTP/1 request bodies at 32 MiB; larger blobs use upload sessions.
    STRONGBOX_MAX_SINGLE_UPLOAD_BYTES = "16777216"
  }
}

resource "google_project_service" "apis" {
  for_each = toset([
    "cloudkms.googleapis.com",
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "servicenetworking.googleapis.com",
    "monitoring.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# ---------------------------------------------------------------------------------------------
# Identities. Each runtime gets its own service account with only what it needs.
# ---------------------------------------------------------------------------------------------
resource "google_service_account" "api" {
  account_id   = "${var.name}-api"
  display_name = "Strongbox API (holds KMS, bucket and database access)"
}

resource "google_service_account" "mcp" {
  account_id   = "${var.name}-mcp"
  display_name = "Strongbox MCP server (API client only; no keys, no data stores)"
}

# Runs migrations and admin commands. Member of strongbox_owner; the API login is not.
resource "google_service_account" "migrate" {
  account_id   = "${var.name}-migrate"
  display_name = "Strongbox migrations and admin (owns the schema; no KMS or bucket access)"
}

resource "google_project_iam_member" "api_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "api_sql_user" {
  project = var.project_id
  role    = "roles/cloudsql.instanceUser"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "api_metrics" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "migrate_sql" {
  for_each = toset(["roles/cloudsql.client", "roles/cloudsql.instanceUser"])
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.migrate.email}"
}

# ---------------------------------------------------------------------------------------------
# Data Access audit logs for the services holding CUI (NIST SP 800-171 3.3.1).
# ---------------------------------------------------------------------------------------------
resource "google_project_iam_audit_config" "data_access" {
  for_each = toset(["cloudkms.googleapis.com", "storage.googleapis.com", "cloudsql.googleapis.com"])
  project  = var.project_id
  service  = each.value
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# Locked log bucket: an independent, retained copy of Strongbox's hash-chained audit events.
# retention_days is ~7 years; set it to your records schedule. Flip `locked` to true once
# retention is confirmed: locking is irreversible.
resource "google_logging_project_bucket_config" "audit" {
  project        = var.project_id
  location       = var.region
  bucket_id      = "${var.name}-audit"
  retention_days = 2555
  locked         = false
}

resource "google_logging_project_sink" "audit" {
  name                   = "${var.name}-audit-events"
  destination            = "logging.googleapis.com/${google_logging_project_bucket_config.audit.id}"
  filter                 = "resource.type=\"cloud_run_revision\" AND jsonPayload.audit=true"
  unique_writer_identity = true
}
