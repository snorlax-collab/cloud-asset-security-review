output "scanner_secret_name" {
  value       = aws_secretsmanager_secret.scanner.name
  description = "Populate with: make set-scanner-secret (reads .env — never put keys in terraform.tfvars)"
}

output "asset_queue_url" {
  value = aws_sqs_queue.asset_scan.url
}

output "reports_bucket" {
  value = aws_s3_bucket.reports.id
}

output "discovery_lambda_arn" {
  value = aws_lambda_function.discovery.arn
}

output "dashboard_s3_uri" {
  value = "s3://${aws_s3_bucket.reports.id}/reports/index.html"
}

output "ecr_repository_url" {
  value = aws_ecr_repository.scanner.repository_url
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.scanner.name
}

output "ecs_service_name" {
  value = aws_ecs_service.worker.name
}

output "deploy_next_steps" {
  value = <<-EOT
    1. Enable CloudTrail management events (org trail recommended).
    2. Build Lambda zip + push scanner image:
         make deploy-build-lambda
         make deploy-push-image AWS_REGION=${var.aws_region}
    3. Populate secrets (NOT via Terraform — avoids secrets in tfstate):
         make set-scanner-secret AWS_REGION=${var.aws_region}
    4. Re-apply if you changed scanner_image: terraform apply
    5. Dashboard (after first scan + sync): terraform output dashboard_s3_uri
    6. Tail worker logs: aws logs tail /ecs/${local.name}-worker --follow
  EOT
}
