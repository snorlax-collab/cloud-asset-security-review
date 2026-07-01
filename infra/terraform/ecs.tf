data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "worker" {
  name        = "${local.name}-worker"
  description = "Scanner workers: no ingress; egress to internet only (RFC1918/IMDS denied at NACL)"
  vpc_id      = data.aws_vpc.default.id
  tags        = local.tags

  # No ingress rules — tasks are not reachable from outside.

  egress {
    description = "Internet egress for scan probes and AWS/Slack/Anthropic APIs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/${local.name}-worker"
  retention_in_days = 14
  tags              = local.tags
}

resource "aws_ecs_cluster" "scanner" {
  name = local.name
  tags = local.tags

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${local.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn
  tags                     = local.tags

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name      = "worker"
    image     = var.scanner_image
    essential = true
    user      = "65534"
    command   = ["worker", "--queue-url", aws_sqs_queue.asset_scan.url, "--out", "/tmp/reports", "--drain-empty", "0"]
    readonlyRootFilesystem = true
    linuxParameters = {
      capabilities = {
        drop = ["ALL"]
      }
      initProcessEnabled = true
    }
    mountPoints = [{
      sourceVolume  = "tmp"
      containerPath = "/tmp"
      readOnly      = false
    }]
    environment = [
      { name = "AWS_DEFAULT_REGION", value = var.aws_region },
      { name = "REPORTS_S3_BUCKET", value = aws_s3_bucket.reports.id },
      { name = "REPORTS_S3_PREFIX", value = "reports" },
      { name = "SLACK_NOTIFY_NEW_ASSETS", value = "true" },
      { name = "SLACK_ALERT_THRESHOLD", value = var.slack_alert_threshold },
    ]
    secrets = [
      { name = "ANTHROPIC_API_KEY", valueFrom = "${aws_secretsmanager_secret.scanner.arn}:ANTHROPIC_API_KEY::" },
      { name = "SLACK_WEBHOOK_URL", valueFrom = "${aws_secretsmanager_secret.scanner.arn}:SLACK_WEBHOOK_URL::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.worker.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "worker"
      }
    }
  }])
}

resource "aws_ecs_service" "worker" {
  name            = "${local.name}-worker"
  cluster         = aws_ecs_cluster.scanner.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"
  tags            = local.tags

  network_configuration {
    subnets          = [aws_subnet.scanner.id]
    security_groups  = [aws_security_group.worker.id]
    assign_public_ip = true
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}
