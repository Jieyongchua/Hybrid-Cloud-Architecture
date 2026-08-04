# Secure Batch File Ingestion Pipeline (Mode B)



This directory contains production-grade Terraform code to provision a secure, event-driven hybrid file-ingestion pipeline.



## Features & Security Design



1\. **Zero Static Credentials:** On-premises servers do not use hardcoded AWS Access Keys. Instead, they authenticate with **AWS IAM Roles Anywhere** using an existing X.509 private certificate issued by your PKI.

2\. **Strict Least-Privilege IAM:** The on-premises dynamic session is permitted *only* to write objects (`PutObject`) to `s3://<bucket>/incoming/*`. 

3\. **Data-at-Rest Protection:** The S3 bucket is completely locked down. All data is encrypted using a Customer Managed KMS Key (CMK) with automated key rotation. No public access is allowed.

4\. **Serverless Processing:** The arrival of a `.csv` file in the `/incoming` directory triggers an automated, lightweight **AWS Lambda** python function which handles parsing, validation, and archiving.



## Prerequisites

* Terraform >= 1.5.0

* An active AWS Account and locally configured CLI.

* An active Private Certificate Authority (such as AWS Private CA or Active Directory Certificate Services) to act as your PKI Trust Anchor.



## Usage

1\. Initialize the directory:

&#x20;  ```bash

&#x20;  terraform init



