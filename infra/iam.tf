# 1. On-Premises Uploader Role (Assumed via Roles Anywhere)
resource "aws_iam_role" "on_prem_uploader_role" {
  name = "${var.project_name}-on-prem-uploader"

  # Trust relationship allowing Roles Anywhere to assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "rolesanywhere.amazonaws.com"
        }
        Action = [
          "sts:AssumeRole",
          "sts:TagSession",
          "sts:SetSourceIdentity"
        ]
      }
    ]
  })
}

# Least-Privilege Policy for On-Premises Role (Write-Only)
resource "aws_iam_policy" "s3_upload_policy" {
  name        = "${var.project_name}-s3-write-policy"
  description = "Allows upload only to S3 incoming prefix"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.ingest_bucket.arn}/incoming/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = [aws_kms_key.s3_key.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_upload" {
  role       = aws_iam_role.on_prem_uploader_role.name
  policy_arn = aws_iam_policy.s3_upload_policy.arn
}

# 2. Lambda Processing Execution Role
resource "aws_iam_role" "lambda_exec_role" {
  name = "${var.project_name}-lambda-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Least-Privilege Policy for Lambda (Read Incoming, Write Archive, Write Logs)
resource "aws_iam_policy" "lambda_permissions" {
  name = "${var.project_name}-lambda-permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:DeleteObject"
        ]
        Resource = ["${aws_s3_bucket.ingest_bucket.arn}/incoming/*"]
      },
      {
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.ingest_bucket.arn}/archive/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [aws_kms_key.s3_key.arn]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = ["arn:aws:logs:*:*:*"]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_lambda" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_permissions.arn
}
