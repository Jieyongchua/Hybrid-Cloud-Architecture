# Terraform CI/CD Ingestion Pipeline (Task 3)



This directory houses the fully automated, zero-trust deployment engine for our hybrid batch ingestion architecture.



## Pipeline Architecture



The workflow is managed via GitHub Actions and is split into three distinct, secure stages:



1. **Security \& Validation:** Runs syntax verification, formatting alignment, and security scanning via **Checkov** to prevent insecure resource deployments.

2. **Immutable Planning:** Assumes an AWS IAM Role via OIDC (Workload Identity) to generate a binary plan. The plan is exported as a temporary workflow artifact.

3. **Gated Deployment:** Restricts deployment to `main` branch merges. The job is bound to a protected GitHub Environment, halting execution until an authorized team lead reviews the plan artifact and manually approves the deployment.



---



## Scaling to Multi-Environment (Dev, Staging, Prod)



To scale this pipeline across a typical enterprise lifecycle, we implement the following modular design patterns:



### 1. Directory/Backend Isolation (Split State)

We split our configurations into environment folders, ensuring each environment has its own isolated remote backend:

```text

environments/

├── dev/

│   ├── backend.tf  # Points to dev state bucket

│   └── dev.tfvars  # Small instance sizes

├── staging/

│   ├── backend.tf

│   └── staging.tfvars

└── prod/

   ├── backend.tf

   └── prod.tfvars

```

### 2. Parameterized Actions Workflow

We modify the Github Actions workflow to detect which directory changed, dynamically running the jobs against the correct environment inputs:

```yaml

# Example Multi-Environment Matrix / Directory mapping

on:

  push:

    paths:

      - "environments/dev/**"

      - "environments/prod/**"

```

### 3. Environment-Specific Role Isolation

Each environment is bound to its own dedicated AWS Account and IAM OIDC Role:

Dev Runner assumes: arn:aws:iam::dev-account-id:role/github-actions-dev
Prod Runner assumes: arn:aws:iam::prod-account-id:role/github-actions-prod

### 4. Gated Controls per Environment

Dev Environment: No manual approvals required. Applies instantly on push to accelerate development velocity.
Staging Environment: Auto-applies upon successful automated integration test execution.
Production Environment: Requires dual-peer reviews and formal approval from the Release Engineering lead inside the GitHub Environments console.
