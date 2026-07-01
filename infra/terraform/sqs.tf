resource "aws_sqs_queue" "discovery_dlq" {
  name                      = "${local.name}-discovery-dlq"
  message_retention_seconds = 1209600
  tags                      = local.tags
}

resource "aws_sqs_queue" "asset_scan_dlq" {
  name                      = "${local.name}-scan-dlq"
  message_retention_seconds = 1209600
  tags                      = local.tags
}

resource "aws_sqs_queue" "asset_scan" {
  name                       = "${local.name}-scan"
  visibility_timeout_seconds = 300
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 10
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.asset_scan_dlq.arn
    maxReceiveCount     = 3
  })
  tags = local.tags
}
