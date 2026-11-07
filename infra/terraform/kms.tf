# Two HSM-backed keys (FIPS 140 Level 3):
#   * data_kek   - wraps Strongbox's per-object and per-collection data keys (application layer).
#   * infra_cmek - customer-managed encryption for the bucket and Cloud SQL disks (storage layer).
# Separating them means the storage service agents can never unwrap application data keys.

resource "google_kms_key_ring" "this" {
  name       = "${var.name}-keys"
  location   = var.region
  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "data_kek" {
  name            = "${var.name}-data-kek"
  key_ring        = google_kms_key_ring.this.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kek_rotation_period

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "infra_cmek" {
  name            = "${var.name}-infra-cmek"
  key_ring        = google_kms_key_ring.this.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kek_rotation_period

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Only the API's identity can use the data KEK. The MCP server deliberately gets nothing here.
resource "google_kms_crypto_key_iam_member" "api_data_kek" {
  crypto_key_id = google_kms_crypto_key.data_kek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.api.email}"
}

data "google_storage_project_service_account" "gcs" {}

resource "google_project_service_identity" "sql" {
  provider = google-beta
  service  = "sqladmin.googleapis.com"
}

resource "google_kms_crypto_key_iam_member" "gcs_cmek" {
  crypto_key_id = google_kms_crypto_key.infra_cmek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

resource "google_kms_crypto_key_iam_member" "sql_cmek" {
  crypto_key_id = google_kms_crypto_key.infra_cmek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.sql.email}"
}
