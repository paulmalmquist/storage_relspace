variable "project_id" {
  description = "Project inside an Assured Workloads folder (ITAR or IL4/IL5 regime) for CUI."
  type        = string
}

variable "region" {
  description = "U.S. region permitted by your Assured Workloads regime."
  type        = string
  default     = "us-east4"
}

variable "name" {
  description = "Prefix for every resource."
  type        = string
  default     = "strongbox"
}

variable "network_id" {
  description = "VPC self link/ID for private Cloud SQL and Direct VPC egress (e.g. projects/p/global/networks/n). Private services access must already be configured on it."
  type        = string
}

variable "subnetwork_id" {
  description = "Subnet for Cloud Run Direct VPC egress (must have Private Google Access enabled)."
  type        = string
}

variable "bucket_name" {
  description = "Globally unique bucket name for blob ciphertext."
  type        = string
}

variable "api_image" {
  description = "Strongbox image built from this repo's Dockerfile (Go FIPS 140-3 module via GOFIPS140), pushed to an Artifact Registry repo inside the boundary."
  type        = string
}

variable "sql_proxy_image" {
  description = "Cloud SQL Auth Proxy image, mirrored into your Artifact Registry."
  type        = string
  default     = "gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.14.1"
}

variable "db_tier" {
  type    = string
  default = "db-custom-2-7680"
}

variable "api_audience" {
  description = "Custom audience callers request ID tokens for; the API verifies it."
  type        = string
  default     = "strongbox-api"
}

variable "mcp_audience" {
  description = "Audience of user tokens presented to the MCP server (also accepted by the API as X-On-Behalf-Of)."
  type        = string
  default     = "strongbox-mcp"
}

variable "api_invokers" {
  description = "IAM members (service accounts of calling services) allowed to invoke the API, e.g. serviceAccount:mes-sync@p.iam.gserviceaccount.com."
  type        = list(string)
  default     = []
}

variable "mcp_public_url" {
  description = "URL MCP clients use to reach the MCP server (its OAuth protected-resource identifier)."
  type        = string
  default     = "https://strongbox-mcp.internal.example"
}

variable "deploy_mcp" {
  type    = bool
  default = true
}

variable "kek_rotation_period" {
  description = "Automatic rotation for the key-encryption key."
  type        = string
  default     = "7776000s" # 90 days
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "app_env" {
  description = "Environment this deployment serves (dev, test, staging, prod). Requests name an app; the environment comes from here, never from the request."
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "test", "staging", "prod"], var.app_env)
    error_message = "app_env must be dev, test, staging or prod."
  }
}

variable "api_min_instances" {
  type    = number
  default = 1
}

variable "api_max_instances" {
  description = "Upper bound on API instances. Together with db_pool_size it bounds database connections."
  type        = number
  default     = 10
}

variable "api_concurrency" {
  description = "Concurrent requests per API instance. Keep it a small multiple of db_pool_size: requests beyond the pool wait for a connection, bounded by the statement timeout."
  type        = number
  default     = 40
}

variable "db_pool_size" {
  description = "pgx pool size per API instance (STRONGBOX_DB_MAX_CONNS)."
  type        = number
  default     = 10
}

variable "db_max_connections" {
  description = "Cloud SQL max_connections. Must exceed api_max_instances * db_pool_size plus headroom for migrations, admin and the proxy."
  type        = number
  default     = 200
}

variable "blob_noncurrent_retention_days" {
  description = "Days a deleted or overwritten object version is kept before the bucket removes it (see docs/RETENTION.md)."
  type        = number
  default     = 30
}
