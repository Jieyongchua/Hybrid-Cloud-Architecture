output "s3_bucket_name" {
  value       = aws_s3_bucket.ingest_bucket.id
  description = "The name of the created S3 Ingestion Bucket"
}

output "roles_anywhere_profile_arn" {
  value       = aws_rolesanywhere_profile.on_prem_profile.arn
  description = "The Profile ARN for IAM Roles Anywhere authentication"
}

output "roles_anywhere_anchor_arn" {
  value       = aws_rolesanywhere_trust_anchor.on_prem_anchor.arn
  description = "The Trust Anchor ARN for IAM Roles Anywhere"
}
