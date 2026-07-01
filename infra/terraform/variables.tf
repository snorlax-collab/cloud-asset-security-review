variable "project_name" {
  description = "Prefix for all resource names."
  type        = string
  default     = "asset-review"
}

variable "aws_region" {
  description = "Primary deployment region (must match CloudTrail home region for regional events)."
  type        = string
}

variable "worker_desired_count" {
  description = "Number of always-on Fargate scanner tasks."
  type        = number
  default     = 2
}

variable "scanner_image" {
  description = "ECR image URI for scanner workers (build + push before apply)."
  type        = string
}

variable "anthropic_api_key" {
  description = "Anthropic API key for LLM review (stored in Secrets Manager)."
  type        = string
  sensitive   = true
  default     = ""
}

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL (optional)."
  type        = string
  sensitive   = true
  default     = ""
}

variable "slack_alert_threshold" {
  type    = string
  default = "LOW"
}

variable "dashboard_sync_rate" {
  description = "EventBridge schedule expression for dashboard rebuild."
  type        = string
  default     = "rate(5 minutes)"
}

variable "tags" {
  type    = map(string)
  default = {}
}
