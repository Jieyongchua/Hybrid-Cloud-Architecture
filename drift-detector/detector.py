#!/usr/bin/env python3
import json
import re
import sys
import os

def load_input_file(filepath):
    """Loads the file and determines if it is a JSON plan or a Git Diff."""
    if not os.path.exists(filepath):
        print(f"ERROR: Target file not found at {filepath}")
        sys.exit(1)
        
    with open(filepath, 'r') as f:
        content = f.read().strip()
        
    # Auto-detect format
    try:
        data = json.loads(content)
        return "json", data
    except json.JSONDecodeError:
        return "diff", content

# ==========================================
# SECURITY RULE EVALUATION ENGINE
# ==========================================
def analyze_json_plan(plan_data):
    """Parses Terraform Plan JSON and flags security risks."""
    findings = []
    
    resource_changes = plan_data.get("resource_changes", [])
    for change in resource_changes:
        address = change.get("address", "")
        change_info = change.get("change", {})
        after = change_info.get("after", {}) or {}
        before = change_info.get("before", {}) or {}
        actions = change_info.get("actions", [])
        
        # Rule 1: Security Group opening ports to 0.0.0.0/0
        if "aws_security_group_rule" in address or "aws_security_group" in address:
            cidr_blocks = after.get("cidr_blocks", [])
            # Also check for single string representation if applicable
            if not isinstance(cidr_blocks, list):
                cidr_blocks = [cidr_blocks]
                
            if "0.0.0.0/0" in cidr_blocks:
                from_port = after.get("from_port", 0)
                to_port = after.get("to_port", 0)
                
                # [...](asc_slot://start-slot-1)Check for wide-open ports (0-65535) or sensitive ports
                is_wide_open = (from_port == 0 and to_port == 65535) or (from_port == to_port and from_port in sensitive_ports)
                
                risk_level = "HIGH" if is_wide_open else "MEDIUM"
                reasoning = (
                    f"Exposing the resource to the entire public internet (0.0.0.0/0) "
                    f"on ports {from_port}-{to_port} represents a massive attack surface increase."
                )
                recommendation = (
                    "Restrict the cidr_blocks to your corporate VPN/on-premises CIDR ranges "
                    "(e.g., 10.0.0.0/8) and close unused ports."
                )
                
                findings.append({
                    "change_description": f"Public network exposure on {address}",
                    "risk_level": risk_level,
                    "reasoning": reasoning,
                    "recommendation": recommendation
                })

        # Rule 2: Wildcard IAM Permissions (Action or Resource = "*")
        if "aws_iam_policy" in address:
            policy_json_str = after.get("policy", "")
            if policy_json_str:
                try:
                    policy = json.loads(policy_json_str)
                    statements = policy.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                        
                    for stmt in statements:
                        effect = stmt.get("Effect", "")
                        actions = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])
                        
                        if effect == "Allow":
                            has_wildcard_action = "*" in actions or (isinstance(actions, list) and "*" in actions)
                            has_wildcard_resource = "*" in resources or (isinstance(resources, list) and "*" in resources)
                            
                            if has_wildcard_action or has_wildcard_resource:
                                findings.append({
                                    "change_description": f"Overly permissive wildcard IAM Policy on {address}",
                                    "risk_level": "HIGH",
                                    "reasoning": "IAM Policy permits administrative wildcard '*' actions/resources, violating least-privilege.",
                                    "recommendation": "Explicitly define allowed IAM actions and restrict target ARNs."
                                })
                except Exception as e:
                    pass # Ignore invalid json inside policy attributes

        # Rule 3: Removal of Encryption
        if "aws_s3_bucket" in address or "aws_kms" in address:
            # Check if an encryption config was present 'before' but is null/disabled 'after'
            before_enc = before.get("server_side_encryption_configuration", {})
            after_enc = after.get("server_side_encryption_configuration", {})
            
            if before_enc and not after_enc:
                findings.append({
                    "change_description": f"Removal of server-side encryption on {address}",
                    "risk_level": "HIGH",
                    "reasoning": "Disabling server-side S3/KMS encryption exposes sensitive data at rest to extraction.",
                    "recommendation": "Re-enable KMS encryption with Customer Managed Keys (CMK) immediately."
                })

        # Rule 4: Network ACL or Firewall changes
        if "aws_network_acl" in address or "aws_route_table" in address:
            if "update" in actions or "delete" in actions:
                findings.append({
                    "change_description": f"Modification of Network ACL or Firewall Rule on {address}",
                    "risk_level": "MEDIUM",
                    "reasoning": "Modifying critical network routing or NACL boundaries risks bypassing security zones.",
                    "recommendation": "Peer-review network routing changes with the Security Operations Team."
                })

	# ADDITIONAL RULE 1: Verify S3 Public Access Block is Active
        if "aws_s3_bucket_public_access_block" in address:
            block_acls = after.get("block_public_acls", False)
            block_policy = after.get("block_public_policy", False)
            ignore_acls = after.get("ignore_public_acls", False)
            restrict_buckets = after.get("restrict_public_buckets", False)
            
            if not (block_acls and block_policy and ignore_acls and restrict_buckets):
                findings.append({
                    "change_description": f"Incomplete Public Access Block on {address}",
                    "risk_level": "HIGH",
                    "reasoning": "S3 buckets must explicitly block all public ACLs, bucket policies, and public access points.",
                    "recommendation": "Set 'block_public_acls', 'block_public_policy', 'ignore_public_acls', and 'restrict_public_buckets' to 'true'."
                })

        # ADDITIONAL RULE 2: Audit EC2 User Data for Plaintext Secrets
        if "aws_instance" in address:
            user_data = after.get("user_data", "")
            if user_data:
                # Regex looking for common secret-assignment patterns
                secrets_pattern = re.compile(r"(?:password|secret|api_key|token|private_key)\s*=\s*['\"].+['\"]", re.IGNORECASE)
                if secrets_pattern.search(user_data):
                    findings.append({
                        "change_description": f"Potential plaintext credential in EC2 user_data on {address}",
                        "risk_level": "HIGH",
                        "reasoning": "Storing credentials or keys inside EC2 user_data exposes them in plaintext to anyone with read-metadata access.",
                        "recommendation": "Inject secrets at runtime using AWS Secrets Manager or Systems Manager Parameter Store."
                    })

        # ADDITIONAL RULE 3: Enforce TLS 1.2+ on Load Balancer Listeners
        if "aws_lb_listener" in address:
            ssl_policy = after.get("ssl_policy", "")
            # Reject outdated TLS policies (e.g., policy standards from 2015/2016 supporting TLS 1.0/1.1)
            if ssl_policy and any(bad_policy in ssl_policy for bad_policy in ["TLS-1-0", "TLS-1-1", "2015", "2016-08"]):
                findings.append({
                    "change_description": f"Insecure TLS policy detected on {address}",
                    "risk_level": "HIGH",
                    "reasoning": "Load balancers must use TLS 1.2 or higher to prevent decryption vulnerability exploits.",
                    "recommendation": "Update 'ssl_policy' to 'ELBSecurityPolicy-TLS13-1-2-2021-06' or higher."
                })


    return findings

def analyze_git_diff(diff_content):
    """Parses a Git Diff output, enforcing advanced rules and correlating multi-line security group changes."""
    findings = []
    
    # State tracking variables for multi-line security group changes
    from_port = None
    to_port = None
    cidr_blocks = []
    
    # 1. Base Security Rule Regular Expressions
    open_port_pattern = re.compile(r"^\+\s*cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"\s*\]")
    wildcard_iam_pattern = re.compile(r"^\+\s*(?:Action|Resource)\s*=\s*\[?\s*\"\*\"\s*\]?")
    encryption_delete_pattern = re.compile(r"^-\s*sse_algorithm\s*=")
    nacl_modification_pattern = re.compile(r"^(?:\+|-)\s*resource\s*\"aws_network_acl")
    
    # 2. Advanced Rule Regular Expressions
    s3_public_block_pattern = re.compile(r"^\+\s*(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false", re.IGNORECASE)
    ec2_user_data_secrets_pattern = re.compile(r"^\+\s*.*(?:password|secret|api_key|token|private_key)\s*=\s*['\"].+['\"]", re.IGNORECASE)
    insecure_tls_policy_pattern = re.compile(r"^\+\s*ssl_policy\s*=\s*['\"].*(?:TLS-1-0|TLS-1-1|2015|2016-08).*['\"]", re.IGNORECASE)
    
    has_public_cidr = False
    
    lines = diff_content.splitlines()
    for line in lines:
        # State Harvester: Extract Ports if they are added/changed in this diff hunk
        if "from_port" in line and "+" in line:
            match = re.search(r"from_port\s*=\s*(\d+)", line)
            if match:
                from_port = int(match.group(1))
                
        if "to_port" in line and "+" in line:
            match = re.search(r"to_port\s*=\s*(\d+)", line)
            if match:
                to_port = int(match.group(1))

        # Detect public CIDR additions
        if open_port_pattern.search(line):
            has_public_cidr = True
            cidr_blocks.append("0.0.0.0/0")
            
        # Detect IAM wildcards
        if wildcard_iam_pattern.search(line):
            findings.append({
                "change_description": "Addition of wildcard '*' IAM permissions detected in diff",
                "risk_level": "HIGH",
                "reasoning": "Modifying IAM policies to include wildcard '*' permissions exposes administrative controls.",
                "recommendation": "Specify exact actions (e.g., s3:PutObject) instead of using '*'"
            })
            
        # Detect encryption removal
        if encryption_delete_pattern.search(line):
            findings.append({
                "change_description": "Deletion of sse_algorithm encryption configuration in diff",
                "risk_level": "HIGH",
                "reasoning": "Removing default encryption configurations on storage assets exposes data at rest.",
                "recommendation": "Retain server-side encryption using a KMS CMK."
            })
            
        # Detect NACL modifications
        if nacl_modification_pattern.search(line):
            findings.append({
                "change_description": "Network ACL resource modified inside diff",
                "risk_level": "MEDIUM",
                "reasoning": "Changing stateless Network ACL rules can inadvertently block internal syncs or expose subnets.",
                "recommendation": "Confirm all rule additions have matching return paths (stateless tracking)."
            })

        # ADVANCED RULE 1: Insecure Public Access Block
        if s3_public_block_pattern.search(line):
            findings.append({
                "change_description": "S3 Public Access Block set to 'false' inside diff",
                "risk_level": "HIGH",
                "reasoning": "Explicitly setting public access blocks to false disables vital S3 bucket security controls.",
                "recommendation": "Ensure public access parameters are set to 'true'."
            })

        # ADVANCED RULE 2: Credentials inside User Data
        if ec2_user_data_secrets_pattern.search(line):
            findings.append({
                "change_description": "Plaintext secret added to EC2 user_data inside diff",
                "risk_level": "HIGH",
                "reasoning": "Adding hardcoded credentials to user_data exposes them in plaintext to AWS console viewers.",
                "recommendation": "Utilize IAM Instance Profiles and AWS Secrets Manager to fetch keys dynamically."
            })

        # [...](asc_slot://start-slot-3)ADVANCED RULE 3: Outdated TLS Policies
        if insecure_tls_policy_pattern.search(line):
            findings.append({
                "change_description": "Outdated or insecure TLS Policy added inside diff",
                "risk_level": "HIGH",
                "reasoning": "Deploying older SSL policies (supporting TLS 1.0 or 1.1) exposes connections to downgrade attacks.",
                "recommendation": "Use 'ELBSecurityPolicy-TLS13-1-2-2021-06' or newer."
            })
            
    # [...](asc_slot://start-slot-7)==========================================
    # CORRELATION ENGINE (Evaluating Harvested State)
    # ==========================================
    if has_public_cidr or ("0.0.0.0/0" in cidr_blocks):
        # Check if we have harvested matching port details in the same diff file
        if from_port is not None and to_port is not None:
            is_wide_open = (from_port == 0 and to_port == 65535)
            risk = "HIGH" if is_wide_open else "MEDIUM"
            
            reasoning = "Adding 0.0.0.0/0 directly exposes security groups to public internet traffic."
            if is_wide_open:
                reasoning += f" Expanding port range to {from_port}-{to_port} exposes ALL network sockets on the VM."
                
            findings.append({
                "change_description": "Public CIDR 0.0.0.0/0 exposure detected in security group diff",
                "risk_level": risk,
                "reasoning": reasoning,
                "recommendation": "Ensure public access is restricted to on-premises IP bounds (10.0.0.0/8)."
            })
        else:
            # Fallback if ports weren't explicitly modified in this commit (stateless default)
            findings.append({
                "change_description": "Public CIDR 0.0.0.0/0 exposure detected in security group diff",
                "risk_level": "MEDIUM",
                "reasoning": "Adding 0.0.0.0/0 directly exposes security groups to public internet traffic.",
                "recommendation": "Ensure public access is restricted to on-premises IP bounds (10.0.0.0/8)."
            })
        
    return findings

# ==========================================
# MAIN EXECUTION CONTROLLER
# ==========================================
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_security.py <path_to_input_file>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    input_type, content = load_input_file(input_file)
    
    print(f"🔍 Analyzing security posture of {input_file} ({input_type.upper()})...")
    
    if input_type == "json":
        reports = analyze_json_plan(content)
    else:
        reports = analyze_git_diff(content)
        
    # Print the structured JSON report to standard output
    print("\n=== SECURITY POLICY ASSESSMENT REPORT ===")
    print(json.dumps(reports, indent=2))
    print("==========================================\n")
    
    # Check if any HIGH risk levels were flagged
    high_risk_found = any(f["risk_level"] == "HIGH" for f in reports)
    
    if high_risk_found:
        print("❌ DEPLOYMENT BLOCKED: Critical security violations with 'HIGH' risk found.")
        sys.exit(1) # Exit with non-zero code to fail the pipeline
    else:
        print("✅ SUCCESS: Security static checks passed successfully.")
        sys.exit(0)

if __name__ == "__main__":
    main()
