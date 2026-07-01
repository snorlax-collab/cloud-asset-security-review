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

variable "slack_alert_threshold" {
  description = "Min severity for Slack alerts (non-secret; set on ECS task env)."
  type        = string
  default     = "LOW"
}

variable "report_retention_days" {
  description = "Expire report objects under reports/ after N days (0 = keep forever)."
  type        = number
  default     = 90
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
