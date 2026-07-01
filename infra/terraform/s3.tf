resource "aws_s3_bucket" "reports" {
  bucket = "${local.name}-reports-${data.aws_caller_identity.current.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration { status = "Enabled" }
}

# Placeholder so dashboard_url output is valid before first sync.
resource "aws_s3_object" "dashboard_placeholder" {
  bucket       = aws_s3_bucket.reports.id
  key          = "reports/index.html"
  content      = "<!doctype html><html><body><h1>Asset Review</h1><p>Waiting for first scan…</p></body></html>"
  content_type = "text/html; charset=utf-8"
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  count  = var.report_retention_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "expire-old-reports"
    status = "Enabled"
    filter { prefix = "reports/" }
    expiration { days = var.report_retention_days }

    noncurrent_version_expiration {
      noncurrent_days = var.report_retention_days
    }
  }
}
