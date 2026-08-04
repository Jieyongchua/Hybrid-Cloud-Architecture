# Customer Managed Key (CMK) for Ingestion Encryption
resource "aws_kms_key" "s3_key" {
  description             = "KMS Key for encrypting hybrid ingestion S3 bucket"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "${var.project_name}-s3-key"
    Environment = var.environment
  }
}

# The Ingestion S3 Bucket
resource "aws_s3_bucket" "ingest_bucket" {
  bucket        = "${var.project_name}-${var.environment}-bucket"
  force_destroy = false

  tags = {
    Name        = "${var.project_name}-bucket"
    Environment = var.environment
  }
}

# Enforce Default Encryption with CMK
resource "aws_s3_bucket_server_side_encryption_configuration" "ingest_enc" {
  bucket = aws_s3_bucket.ingest_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# Block all Public Access (Zero-Trust Perimeter)
resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = aws_s3_bucket.ingest_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enforce secure HTTPS transit only
resource "aws_s3_bucket_policy" "ssl_only" {
  bucket = aws_s3_bucket.ingest_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceSSLRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.ingest_bucket.arn,
          "${aws_s3_bucket.ingest_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
