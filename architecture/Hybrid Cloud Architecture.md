# Task 1: Hybrid Cloud Integration Architecture



## 1. Network Connectivity & Security Perimeter

To satisfy the constraint that the on-premises datacenter has **no direct inbound internet access**, the network topology is designed around a secure, outbound-initiated **Site-to-Site IPSec VPN Tunnel**.



*   **Tunnel Initiation:** The on-premises edge gateway initiates the secure IPSec connection to the cloud network gateway over the public internet. This avoids opening inbound firewall ports on-premises.

*   **Routing:** All communication occurs strictly within private RFC 1918 IP spaces. Private DNS zones are configured to resolve service endpoints to private cloud IPs, avoiding public internet routing entirely.

*   **Segmented Perimeter:** Cloud Security Groups (stateful firewalls) and Network ACLs (stateless subnets) restrict traffic to accept packets only from the specific private IP address of the on-premises legacy VM.



## 2. Mode A: Real-Time API Integration (Pull Flow)

*   **Design:** The legacy application on-premises calls the cloud-native microservice via REST API endpoints to retrieve reference data on demand.

*   **Path:** Legacy VM -> IPSec VPN -> Cloud Private Load Balancer -> Kubernetes Ingress Controller -> Target Pods.

*   **AuthN \& AuthZ Boundary:**

&#x20;   *   **Network Gateway:** Mutual TLS (mTLS) is enforced at the Cloud Ingress/Load Balancer. The legacy VM and Ingress present X.509 certificates from a trusted Private Certificate Authority (CA).

&#x20;   *   **Application Boundary:** The Ingress Controller passes the validated Client Certificate identity headers to the microservice. The service evaluates the identity against an internal access matrix (RBAC) to authorize the specific payload extraction.



\## 3. Mode B: Batch File Ingestion Pipeline (Push Flow)

*   **Design:** A push-based model is implemented since the cloud cannot query the on-premises environment.

*   **Path:** On-Premises File Agent -> Private HTTPS File Upload -> Cloud Object Storage -> Storage Event Trigger -> Serverless Compute -> Target Database.

*   **AuthN \& AuthZ Boundary:**

&#x20;   *   **Storage Gateway:** The local agent uses temporary, short-lived security tokens to authenticate with the storage API. Instead of static API keys, tokens are derived dynamically using local certificate-based identity verification (similar to AWS IAM Roles Anywhere).

&#x20;   *   **Access Policy:** The temporary credentials grant least-privilege permissions limited strictly to write operations (`PutObject`) in a specific directory (`/incoming/`) of the ingestion bucket.

&#x20;   *   **Processing \& DB Boundary:** The serverless function operates under an IAM execution role allowing it to read incoming files, validate schemas, sanitize inputs, write to the database, and move processed files to an archive directory.



## 4. Key Architectural Trade-offs Considered



### Connectivity: IPSec VPN vs. Dedicated Private Circuit (e.g., Direct Connect)

*   **Trade-off:** VPNs are cost-effective, rapid to deploy, and fully encrypted but run over the public internet, meaning throughput and latency are not guaranteed. Dedicated circuits offer stable, high-throughput lines but are expensive and slow to provision.

*   **Decision: IPSec VPN.** Given the workload profile (on-demand reference lookups and nightly batch files), the cost and speed of a VPN align perfectly. A dedicated circuit is reserved for future scaling if batch volumes exceed several gigabytes.



### File Exchange: Private API Upload vs. Managed SFTP Gateway

*   **Trade-off:** A managed SFTP gateway is highly compatible with legacy systems but incurs significant base hourly charges. A direct programmatic upload to cloud object storage via HTTPS avoids those fees and triggers processing events natively.

*   **Decision: Direct Object Storage Upload over VPN.** Using standard SDKs/CLIs with temporary credentials maximizes security, reduces cloud costs, and natively integrates with serverless ingestion triggers.





