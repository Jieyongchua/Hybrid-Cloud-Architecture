import os
import sys
import json
from typing import List, Literal
from pydantic import BaseModel, Field, ValidationError
import google.generativeai as genai

# --- Pydantic Schema Definition ---

class SecurityFinding(BaseModel):
    change_description: str = Field(..., description="Brief description of target resource.")
    risk_level: Literal["LOW", "MEDIUM", "HIGH"] = Field(..., description="The classified risk level.")
    reasoning: str = Field(..., min_length=15, description="Exhaustive explanation of why this risk level is selected.")
    recommendation: str = Field(..., description="Detailed instructions showing how to remediate the code.")

class ComplianceReport(BaseModel):
    reports: List[SecurityFinding]

# --- AI Agent Interaction ---
def load_system_prompt(filepath="drift-detector/ai-agent/prompt.md"):
    if not os.path.exists(filepath):
        print(f"ERROR: System prompt not found at {filepath}")
        sys.exit(1)
    with open(filepath, 'r') as f:
        return f.read()

def handle_unreliable_fallback(raw_ai_text: str, validation_error: Exception) -> List[dict]:
    print("🚨 Safeguard Initiated: Generating High-Risk fallback to protect deployment pipeline.")
    os.makedirs("logs", exist_ok=True)
    with open("logs/ai_error_triage.log", "w") as f:
        f.write(f"ERROR: {str(validation_error)}\\n\\nRAW LLM TEXT:\\n{raw_ai_text}")
   

    fallback_finding = {
        "change_description": "AI Security Auditor Unreliability Event",
        "risk_level": "HIGH",
        "reasoning": f"The AI Security Auditor failed to produce a verifiable, schema-compliant output. Parsing Error: {str(validation_error)[:150]}. The output has been safely intercepted.",
        "recommendation": "Review the raw AI logs inside 'logs/ai_error_triage.log'. Manually audit this pull request before allowing any pipeline deployments."
    }
    return [fallback_finding]

 

def query_ai_security_agent(content_to_analyze: str, system_prompt: str, retries: int = 2) -> List[dict]:
    try:
        genai.configure(api_key=os.environ["GEMINI_API_KEY"])
    except KeyError:
        print("ERROR: GEMINI_API_KEY environment variable not set.")
        return handle_unreliable_fallback("API Key not configured.", Exception("GEMINI_API_KEY not set."))

    model = genai.GenerativeModel(
        model_name="gemini-1.5-pro",
        system_instruction=system_prompt
    )

    schema_str = ComplianceReport.model_json_schema()
    prompt = (
        f"Analyze the following infrastructure changes. "
        f"You MUST format your output to exactly match this JSON schema:\\n{json.dumps(schema_str, indent=2)}\\n\\n"
        f"Input Changes:\\n{content_to_analyze}"
    )
   
    current_prompt = prompt
    for attempt in range(retries + 1):
        try:
            print(f"🧠 Querying AI Security Agent (Attempt {attempt + 1})...")
            response = model.generate_content(current_prompt)
           
            # Clean up potential markdown blocks wrapped around response text
            clean_text = response.text.replace("```json", "").replace("```", "").strip()
           
            # Pydantic strictly validates the JSON against the schema
            report_data = json.loads(clean_text)
            validated_report = ComplianceReport(reports=report_data)
           
            print("✅ SUCCESS: AI Agent returned schema-compliant results.")
            return [item.model_dump() for item in validated_report.reports]
        except (ValidationError, json.JSONDecodeError) as err:
            print(f"⚠️ WARNING: AI generated an invalid or malformed schema on attempt {attempt + 1}.")
           
            if attempt < retries:
                print("🔄 Executing Auto-Correction loop with model feedback...")
                current_prompt = (
                    f"{prompt}\\n\\n"
                    f"Your previous attempt failed validation with the following error:\\n{str(err)}\\n"
                    f"Please correct your formatting and return valid, schema-compliant JSON."
                )
            else:
                print("❌ ERROR: AI Agent failed to produce reliable results after multiple attempts.")
                raw_text = response.text if 'response' in locals() else 'No response received from model.'
                return handle_unreliable_fallback(raw_text, err)
 
# --- Main Execution Block ---
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ai-agent/agent.py <path_to_input_file>")
        sys.exit(1)
       
    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"ERROR: Input file not found at {input_file}")
        sys.exit(1)
       
    with open(input_file, 'r') as f:
        content = f.read()
 
    system_prompt = load_system_prompt()
    reports = query_ai_security_agent(content, system_prompt)
 
    print("\n=== LLM-POWERED SECURITY ASSESSMENT REPORT ===")
    print(json.dumps(reports, indent=2))
    print("=============================================\n")
 
    high_risk_found = any(f.get("risk_level") == "HIGH" for f in reports)
   
    if high_risk_found:
        print("❌ DEPLOYMENT BLOCKED: Critical security violations with 'HIGH' risk found.")
        sys.exit(1)
    else:
        print("✅ SUCCESS: Security static checks passed successfully.")
        sys.exit(0)
 
if __name__ == "__main__":
    main()
