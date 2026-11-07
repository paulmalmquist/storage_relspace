output "api_url" {
  value = google_cloud_run_v2_service.api.uri
}

output "mcp_url" {
  value = var.deploy_mcp ? google_cloud_run_v2_service.mcp[0].uri : null
}

output "data_kek" {
  value = google_kms_crypto_key.data_kek.id
}

output "bucket" {
  value = google_storage_bucket.blobs.name
}

output "sql_connection_name" {
  value = google_sql_database_instance.pg.connection_name
}

output "api_service_account" {
  value = google_service_account.api.email
}

output "mcp_service_account" {
  value = google_service_account.mcp.email
}
