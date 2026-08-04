# Task 6: Automated Security Guardrail & Drift Scanner

 

This directory houses our unified **Shift-Left Security Compliance Suite**. It includes a lightweight, ultra-high-speed programmatic Python scanner and an advanced, LLM-powered safety auditor designed to intercept insecure configurations before they are deployed to our AWS hybrid environment.



---

 

## 🔒 Monitored Security Risks & Mitigation Rules

 

Our compliance suite implements precise heuristics and structural checks to block the following high-risk configurations:

 

### 1. Public Network Exposure (HIGH)

*   **The Hazard:** Opening port ranges to the public internet (`0.0.0.0/0`) allows attackers to scan and exploit host vulnerabilities directly.

*   **The Check:** Detects the addition of `0.0.0.0/0` to `cidr_blocks` in `aws_security_group_rule`. If paired with wide-open port ranges (e.g., `0-65535`) or sensitive ports (such as SSH `22` or RDP `3389`), the risk is upgraded to **`HIGH`**.

 

### 2. Wildcard Administrative Permissions (HIGH)

*   **The Hazard:** Granting `Action: "*"` or `Resource: "*"` in IAM policies violates the principle of least privilege, enabling malicious privilege escalations.

*   **The Check:** Audits `aws_iam_policy` resources and blocks any statement combining `"Effect": "Allow"` with wildcard variables.

 

### 3. Data Protection & Cryptographic Failures (HIGH)

*   **The Hazard:** Disabling or downgrading storage encryption exposes sensitive batch transaction files at rest.

*   **The Check:** Detects deletions of `server_side_encryption_configuration` on S3 buckets or the use of deprecated SSL policies (e.g., TLS 1.0 or 1.1) on load balancer listeners (`aws_lb_listener`).

 

### 4. Network Perimeter Modifications (MEDIUM)

*   **The Hazard:** Changing stateless Network ACL rules can bypass security perimeters or break outbound-initiated synchronization channels.

*   **The Check:** Flags any modifications to `aws_network_acl` or network routing tables for mandatory human peer review.

 

---

 

## 🛠️ Configuration & Installation

 

### Prerequisites

Ensure your local host or CI/CD runner has Python 3.10+ installed.

 

```bash

# Install required validation and client libraries

python3 -m pip install google-generativeai pydantic


## Usage & Verification


### Running Rule-Based Scanner

python3 drift-detector/detector.py drift-detector/fixtures/sample.diff
python3 drift-detector/detector.py drift-detector/fixtures/sample_plan.json



### Running LLM-Power Auditor

export GEMINI_API_KEY="YOUR_API_KEY"
python3 drift-detector/ai-agent/agent.py sample.diff
python3 drift-detector/ai-agent/agent.py sample.diff
