# Tier-1 CloudTrail events → discovery Lambda (see infra/eventbridge-rules.json).
resource "aws_cloudwatch_event_rule" "tier1" {
  name        = "${local.name}-tier1-discovery"
  description = "Born-public / directly scannable CloudTrail create events"

  event_pattern = jsonencode({
    source = [
      "aws.route53", "aws.route53domains", "aws.elasticloadbalancing", "aws.ec2",
      "aws.apigateway", "aws.lambda", "aws.cloudfront", "aws.rds", "aws.s3",
    ]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "ChangeResourceRecordSets", "CreateHostedZone", "RegisterDomain",
        "CreateLoadBalancer",
        "CreateRestApi", "CreateApi", "CreateDomainName",
        "CreateFunctionUrlConfig", "UpdateFunctionUrlConfig",
        "CreateDistribution", "CreateDistributionWithTags",
        "RunInstances", "AssociateAddress",
        "CreateDBInstance", "ModifyDBInstance",
        "CreateBucket", "PutBucketAcl", "PutBucketPolicy", "DeleteBucketPublicAccessBlock",
      ]
      errorCode = [{ exists = false }]
    }
  })

  tags = local.tags
}

resource "aws_cloudwatch_event_target" "tier1_discovery" {
  rule      = aws_cloudwatch_event_rule.tier1.name
  target_id = "discovery-lambda"
  arn       = aws_lambda_function.discovery.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 4
  }

  dead_letter_config {
    arn = aws_sqs_queue.discovery_dlq.arn
  }
}
