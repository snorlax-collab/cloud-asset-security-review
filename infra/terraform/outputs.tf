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
    2. Build and push the scanner image:
         make deploy-push-image AWS_REGION=${var.aws_region}
    3. Re-apply if you changed scanner_image: terraform apply
    4. Dashboard (after first scan + sync): terraform output dashboard_s3_uri
    5. Tail worker logs: aws logs tail /ecs/${local.name}-worker --follow
  EOT
}
