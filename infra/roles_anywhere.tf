# Roles Anywhere Trust Anchor (Trusts your On-Premises PKI/CA)
resource "aws_rolesanywhere_trust_anchor" "on_prem_anchor" {
  name    = "${var.project_name}-trust-anchor"
  enabled = true

  source {
    source_data {
      acm_pca_arn = var.on_prem_ca_arn
    }
    source_type = "AWS_ACM_PCA"
  }
}

# Roles Anywhere Profile (Applies policies to assumed sessions)
resource "aws_rolesanywhere_profile" "on_prem_profile" {
  name      = "${var.project_name}-profile"
  enabled   = true
  role_arns = [aws_iam_role.on_prem_uploader_role.arn]
}
