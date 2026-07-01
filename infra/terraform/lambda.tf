resource "aws_cloudwatch_log_group" "discovery" {
  name              = "/aws/lambda/${local.name}-discovery"
  retention_in_days = 14
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "dashboard_sync" {
  name              = "/aws/lambda/${local.name}-dashboard-sync"
  retention_in_days = 14
  tags              = local.tags
}

resource "null_resource" "lambda_package" {
  triggers = {
    src = sha256(join("", [
      for f in fileset("${path.module}/../../src/asset_review", "**/*.py") :
      filesha256("${path.module}/../../src/asset_review/${f}")
    ]))
  }

  provisioner "local-exec" {
    command     = "${path.module}/../../scripts/build_lambda_zip.sh"
    working_dir = path.module
  }
}

data "archive_file" "lambda" {
  depends_on  = [null_resource.lambda_package]
  type        = "zip"
  source_dir  = "${path.module}/../../dist/lambda"
  output_path = "${path.module}/../../dist/lambda.zip"
}

resource "aws_lambda_function" "discovery" {
  function_name = "${local.name}-discovery"
  role          = aws_iam_role.discovery.arn
  handler       = "asset_review.discovery.lambda_handler.handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 256
  filename      = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      ASSET_QUEUE_URL = aws_sqs_queue.asset_scan.url
    }
  }

  depends_on = [aws_cloudwatch_log_group.discovery]
  tags       = local.tags
}

resource "aws_lambda_function" "dashboard_sync" {
  function_name = "${local.name}-dashboard-sync"
  role          = aws_iam_role.dashboard_sync.arn
  handler       = "asset_review.storage.lambda_handler.handler"
  runtime       = "python3.12"
  timeout       = 120
  memory_size   = 512
  filename      = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      REPORTS_S3_BUCKET = aws_s3_bucket.reports.id
      REPORTS_S3_PREFIX = "reports"
    }
  }

  depends_on = [aws_cloudwatch_log_group.dashboard_sync]
  tags       = local.tags
}

resource "aws_lambda_permission" "discovery_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.discovery.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.tier1.arn
}

resource "aws_lambda_permission" "dashboard_sync_schedule" {
  statement_id  = "AllowEventBridgeSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.dashboard_sync.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.dashboard_sync.arn
}

resource "aws_cloudwatch_event_target" "dashboard_sync" {
  rule      = aws_cloudwatch_event_rule.dashboard_sync.name
  target_id = "dashboard-sync"
  arn       = aws_lambda_function.dashboard_sync.arn
}

resource "aws_cloudwatch_event_rule" "dashboard_sync" {
  name                = "${local.name}-dashboard-sync"
  description         = "Rebuild HTML dashboard from S3 report JSON"
  schedule_expression = var.dashboard_sync_rate
  tags                = local.tags
}
