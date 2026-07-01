resource "aws_secretsmanager_secret" "scanner" {
  name = "${local.name}/scanner"
  tags = local.tags
}

resource "aws_secretsmanager_secret_version" "scanner" {
  secret_id = aws_secretsmanager_secret.scanner.id
  secret_string = jsonencode({
    ANTHROPIC_API_KEY     = var.anthropic_api_key
    SLACK_WEBHOOK_URL     = var.slack_webhook_url
    SLACK_ALERT_THRESHOLD = var.slack_alert_threshold
  })
}

data "aws_iam_policy_document" "discovery_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "discovery" {
  name               = "${local.name}-discovery"
  assume_role_policy = data.aws_iam_policy_document.discovery_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "discovery" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.asset_scan.arn]
  }
  statement {
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
  }
}

resource "aws_iam_role_policy" "discovery" {
  name   = "discovery"
  role   = aws_iam_role.discovery.id
  policy = data.aws_iam_policy_document.discovery.json
}

data "aws_iam_policy_document" "dashboard_sync_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "dashboard_sync" {
  name               = "${local.name}-dashboard-sync"
  assume_role_policy = data.aws_iam_policy_document.dashboard_sync_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "dashboard_sync" {
  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.reports.arn]
  }
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.reports.arn}/*"]
  }
  statement {
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
  }
}

resource "aws_iam_role_policy" "dashboard_sync" {
  name   = "dashboard-sync"
  role   = aws_iam_role.dashboard_sync.id
  policy = data.aws_iam_policy_document.dashboard_sync.json
}

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_execution" {
  name               = "${local.name}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "ecs_execution_secrets" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.scanner.arn]
  }
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name   = "secrets"
  role   = aws_iam_role.ecs_execution.id
  policy = data.aws_iam_policy_document.ecs_execution_secrets.json
}

resource "aws_iam_role" "ecs_task" {
  name               = "${local.name}-ecs-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "ecs_task" {
  statement {
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ChangeMessageVisibility",
    ]
    resources = [aws_sqs_queue.asset_scan.arn]
  }
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.reports.arn}/reports/*"]
  }
}

resource "aws_iam_role_policy" "ecs_task" {
  name   = "worker"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.ecs_task.json
}
