variable "aws_region" {
  type        = string
  description = "The target AWS region for deployment"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "The deployment environment (e.g., dev, staging, prod)"
  default     = "prod"
}

variable "project_name" {
  type        = string
  description = "The prefix used for naming resources"
  default     = "hybrid-ingest"
}

variable "on_prem_ca_arn" {
  type        = string
  description = "The ARN of the Active Directory or Private CA in AWS (or external ACM PCA ARN)"
  default     = "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012"
}
