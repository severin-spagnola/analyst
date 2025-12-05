from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import anthropic
import os
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

class ScanRequest(BaseModel):
    target: str

@app.post("/scan")
async def run_security_scan(request: ScanRequest):
    target = request.target
    
    # Run quick nmap scan
    print(f"Scanning {target}...")
    nmap_result = subprocess.run(
        ['nmap', '-sV', '-F', target],
        capture_output=True,
        text=True,
        timeout=60
    )
    
    # Run nikto if it's a web target
    nikto_result = subprocess.run(
        ['nikto', '-h', f'http://{target}', '-Tuning', '1,2,3'],
        capture_output=True,
        text=True,
        timeout=60
    )
    
    raw_output = f"""
    === NMAP SCAN ===
    {nmap_result.stdout}
    
    === NIKTO WEB SCAN ===
    {nikto_result.stdout}
    """
    
    # Send to Claude for analysis
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        messages=[{
            "role": "user",
            "content": f"""You are a cybersecurity analyst. Analyze this security scan output and provide:

1. Top 3 critical vulnerabilities found
2. Risk level (Critical/High/Medium/Low) for each
3. Specific remediation steps with commands where applicable
4. Executive summary in plain English

Format your response clearly with headers.

SCAN OUTPUT:
{raw_output}
"""
        }]
    )
    
    return {
        "raw_output": raw_output,
        "ai_analysis": message.content[0].text
    }

@app.get("/")
async def root():
    return {"status": "CyberSec AI Agent API running"}