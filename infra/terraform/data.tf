# ---------------------------------------------------------------------------------------------
# Blob ciphertext bucket
# ---------------------------------------------------------------------------------------------
resource "google_storage_bucket" "blobs" {
  name                        = var.bucket_name
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  encryption {
    default_kms_key_name = google_kms_crypto_key.infra_cmek.id
  }

  versioning {
    enabled = true
  }

  soft_delete_policy {
    retention_duration_seconds = 604800
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 3
      with_state         = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.gcs_cmek]
}

resource "google_storage_bucket_iam_member" "api_objects" {
  bucket = google_storage_bucket.blobs.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.api.email}"
}

# ---------------------------------------------------------------------------------------------
# Cloud SQL for PostgreSQL: private IP only, TLS only, CMEK, IAM database authentication.
# ---------------------------------------------------------------------------------------------
resource "google_sql_database_instance" "pg" {
  name                = "${var.name}-pg"
  database_version    = "POSTGRES_16"
  region              = var.region
  encryption_key_name = google_kms_crypto_key.infra_cmek.id
  deletion_protection = var.deletion_protection

  settings {
    tier              = var.db_tier
    availability_type = "REGIONAL"
    disk_autoresize   = true

    ip_configuration {
      ipv4_enabled    = false
      private_network = var.network_id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.sql_cmek]
}

resource "google_sql_database" "strongbox" {
  name     = "strongbox"
  instance = google_sql_database_instance.pg.name
}

resource "google_sql_user" "api" {
  name     = local.api_db_user
  instance = google_sql_database_instance.pg.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}
