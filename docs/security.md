\# Task 5: Security Considerations



This document outlines the top three security risks identified in our hybrid cloud integration design and the concrete, non-generic cryptographic and architectural controls implemented to mitigate each one.



\---



\## Risk 1: Compromise of the On-Premises Legacy VM Private Key (`client.key`)



\* \*\*Threat Scenario:\*\* 

&#x20; An attacker gains unauthorized access to the on-premises legacy VM (e.g., via a compromised local credential or OS privilege escalation) and extracts the unencrypted private key file (`client.key`). Using this stolen key, the attacker bypasses physical network boundaries, connects over the public internet, and directly executes mTLS handshakes with our Cloud Ingress (Mode A) or initiates IAM Roles Anywhere sessions (Mode B), gaining unauthorized access to cloud resources.

\* \*\*Mitigation Controls:\*\*

&#x20; 1. \*\*TPM-Backed Key Storage:\*\* The private key is stored within a physical \*\*Trusted Platform Module (TPM 2.0)\*\* or a secure local Hardware Security Module (HSM) on the on-premises host. The key is flagged as \*non-exportable\* to prevent raw extraction from memory or disk.

&#x20; 2. \*\*Cryptographic Signing Handshake:\*\* All mTLS and IAM Roles Anywhere handshakes utilize standard local cryptographic APIs (such as PKCS#11) that execute key signing operations \*directly inside\* the secure boundary of the TPM hardware. The raw private key material is never exposed in system memory.

&#x20; 3. \*\*Short-Lived Sessions:\*\* AWS IAM Roles Anywhere session durations are limited to a maximum of \*\*15 minutes\*\* (using the `duration\_seconds` parameter in Terraform), significantly limiting the utility of any temporarily hijacked sessions.



\---



\## Risk 2: Public Object Storage Data Leakage via Configuration Drift



\* \*\*Threat Scenario:\*\* 

&#x20; A cloud administrator manually modifies the properties of our ingestion S3 bucket during a troubleshooting session. They inadvertently disable the "Block Public Access" setting or alter the bucket policy to allow unrestricted reading of objects. This instantly exposes sensitive, unencrypted nightly CSV transactions containing corporate data to the public internet.

\* \*\*Mitigation Controls:\*\*

&#x20; 1. \*\*Immutable KMS Key Encryption:\*\* The bucket is configured with default server-side encryption using a \*\*Customer Managed Key (CMK)\*\* inside \*\*AWS KMS\*\*. The KMS key policy restricts the `kms:Decrypt` action exclusively to our serverless Lambda IAM execution role. Even if the S3 bucket is accidentally exposed, unauthorized attackers downloading files will receive only encrypted cipher text.

&#x20; 2. \*\*Automated Drift Detection \& Healing:\*\* We configure \*\*AWS Config\*\* with the managed rule `s3-bucket-public-write-prohibited` or `s3-bucket-level-public-access-prohibited`.

&#x20; 3. \*\*Auto-Remediation:\*\* Upon detecting a public change, AWS Config fires an event that triggers an \*\*AWS Systems Manager (SSM) Automation\*\* document. The automation script automatically reverts the manual changes, locking the bucket back down to "Block All Public Access" within 60 seconds.



\---



\## Risk 3: Compromise of the Certificate Authority (Root CA Trust Anchor)



\* \*\*Threat Scenario:\*\* 

&#x20; Our internal Private Certificate Authority (CA) is compromised by a malicious insider or sophisticated threat actor. The attacker uses the compromised CA's private key to sign a valid, rogue X.509 client certificate containing the Common Name matching our legacy VM. Because the cloud gateways trust the CA root, they will authorize this rogue certificate on presentation.

\* \*\*Mitigation Controls:\*\*

&#x20; 1. \*\*Two-Tier PKI Architecture:\*\* We use a two-tier PKI layout. The Root CA remains completely offline in a physically locked container. It only signs the certificate of an online Intermediate Sub-CA, which is what signs our VM client certificates.

&#x20; 2. \*\*Active Certificate Revocation Lists (CRL):\*\* We enforce active \*\*CRL validation\*\* at our EKS Ingress Controller (using NGINX's `ssl\_crl` parameter) and AWS Roles Anywhere (using the `crl\_data` attribute). If a certificate or Sub-CA is suspected of compromise, its serial number is published to the CRL, instantly blocking access to any client presenting that certificate.

&#x20; 3. \*\*Attribute-Based Access Control (ABAC):\*\* In our AWS Roles Anywhere profile, we configure a strict trust validation mapping. The assumed role is blocked unless the incoming client certificate presents a highly specific, custom \*\*Subject Alternative Name (SAN)\*\* extension representing our exact server department ID, acting as a critical secondary check.



