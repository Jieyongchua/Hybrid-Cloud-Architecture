# Package the Python code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_code"
  output_path = "${path.module}/lambda_function.zip"
}

# The Lambda Function Resource
resource "aws_lambda_function" "csv_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-csv-processor"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "index.handler"
  runtime          = "python3.11"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      INGEST_BUCKET = aws_s3_bucket.ingest_bucket.id
    }
  }

  tags = {
    Environment = var.environment
  }
}

# Give S3 Permission to trigger Lambda
resource "aws_lambda_permission" "allow_s3_trigger" {
  statement_id  = "AllowS3TriggerCsvProcessor"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.csv_processor.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.ingest_bucket.arn
}

# S3 Notification Config (Triggers Lambda on file arrival)
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.ingest_bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.csv_processor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "incoming/"
    filter_suffix       = ".csv"
  }

  depends_on = [aws_lambda_permission.allow_s3_trigger]
}
