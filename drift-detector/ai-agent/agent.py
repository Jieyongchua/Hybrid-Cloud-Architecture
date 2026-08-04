import google.generativeai as genai
import json
import os
import sys

# Configure API Access
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))

def load_system_prompt(filepath="ai-agent/prompt.md"):
    with open(filepath, 'r') as f:
        return f.read()

def analyze_changes_with_llm(change_content):
    system_prompt = load_system_prompt()
    
    # Initialize the Gemini Pro Model
    model = genai.GenerativeModel(
        model_name="gemini-1.5-pro",
        system_instruction=system_prompt
    )
    
    # Send the plan/diff for security review
    response = model.generate_content(
        f"Please analyze the following infrastructure changes and return the structured JSON report:\n\n{change_content}"
    )
    
    try:
        # Strip markdown block wrappers if returned by the LLM
        clean_text = response.text.replace("```json", "").replace("```", "").strip()
        report = json.loads(clean_text)
        return report
    except json.JSONDecodeError as e:
        # FALLBACK SAFETY INTERCEPTION: If the LLM returned invalid JSON, create a safe fallback
        print("⚠️ WARNING: LLM returned unparsable JSON. Executing Fallback Protocol...")
        return [{
            "change_description": "Failed to parse LLM response.",
            "risk_level": "HIGH",
            "reasoning": f"The AI security agent's output could not be parsed as JSON. Raw output: {response.text}",
            "recommendation": "Halt deployment and request a manual review of both the infrastructure code and the AI model's health."
        }]
