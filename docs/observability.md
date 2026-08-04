# Task 4: Observability Design



This framework establishes an end-to-end observability strategy to ensure the reliability and performance of the hybrid cloud integration, covering real-time APIs (Mode A) and batch file transfers (Mode B). The design is centered on three core pillars: proactive monitoring and alerting, cross-boundary log correlation, and actionable SRE runbooks.



---



## 1. Instrumentation \& Alerting Strategy



To provide comprehensive visibility, we monitor key performance indicators (KPIs) across both on-premises and cloud environments, with targeted alerts to notify Site Reliability Engineering (SRE) teams of anomalies.



### Mode A (Real-Time API)

We monitor the health of the API request path by tracking **VPN tunnel latency**, **mTLS handshake success/failure rates**, and **Kubernetes Ingress HTTP 5xx/4xx error rates**.

* **Critical Alert:** A `P2` alert is triggered if the Ingress controller’s HTTP 5xx error rate exceeds **2%** over a 5-minute window, indicating a service outage.



### Mode B (Batch File Ingestion)

We monitor the state of the nightly file transfer by tracking **on-premises agent logs**, **S3 `PutObject` call metrics**, and **AWS Lambda execution health** (duration, errors, invocations).

* **Critical Alert:** A `P1` "Dead-Man’s-Switch" alert is triggered if the expected nightly batch file (`nightly\_data\_\*.csv`) **fails to arrive** in the S3 bucket by **03:00 AM UTC**, indicating a complete pipeline failure.



---



## 2. Cross-Boundary Telemetry Correlation



To create a unified view of transactions as they cross from the on-premises datacenter to the AWS cloud, we implement a **Correlation ID** model based on the W3C Trace Context standard.



1. **ID Injection:** A unique `X-Correlation-ID` is generated on-premises at the start of each transaction.

2. **Header \& Metadata Propagation:** This ID is injected into the **HTTP headers** of API calls (Mode A) and attached as **S3 Object Metadata** (`x-amz-meta-correlation-id`) during file uploads (Mode B).

3. **Unified View:** All on-premises (syslog) and cloud (CloudWatch, CloudTrail) logs are forwarded to a central SIEM platform (e.g., Splunk). SREs can use the shared Correlation ID to query the exact end-to-end journey of any transaction, seamlessly stitching together logs from disparate systems.



---



## 3. SRE Runbook Summary: Failed Nightly File Transfer



In the event of a file ingestion failure, this runbook provides a clear, step-by-step diagnostic path.



### I. Triage

The on-call engineer first determines the failure location by checking if the file landed in the S3 `/incoming/` directory.

* **If the file is absent**, the issue is on-premises. The engineer inspects the local file-watcher agent logs (`/var/log/ingest-agent/upload.log`) and VPN tunnel status. Common causes include expired local X.509 certificates or network connectivity loss.

* **If the file is present**, the issue is in the cloud. The engineer inspects the AWS Lambda processor's CloudWatch logs for runtime exceptions. Common causes include CSV schema validation errors or database connection timeouts.



### II. Resolution

Once the root cause is identified and fixed (e.g., certificate renewed, database rebooted), the on-premises operator is instructed to manually re-trigger the upload script to re-process the file.



