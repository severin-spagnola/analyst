from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import anthropic
import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

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
    target: str = "network"  # Default to scanning the network

@app.post("/scan")
async def run_security_scan(request: ScanRequest):
    # Scan the local "network" - our Docker containers
    targets = [
        ("localhost", "8080", "Web Application Server (DVWA)"),
        ("localhost", "8081", "WordPress Server"),
        ("localhost", "3306", "Database Server (MySQL)"),
    ]
    
    all_scans = []
    
    for host, port, description in targets:
        print(f"Scanning {description} on {host}:{port}...")
        
        try:
            # Quick nmap scan on specific port
            nmap_result = subprocess.run(
                ['nmap', '-sV', '-p', port, host],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            all_scans.append(f"""
=== {description} ===
Target: {host}:{port}
{nmap_result.stdout}
""")
        except subprocess.TimeoutExpired:
            all_scans.append(f"=== {description} ===\nScan timeout\n")
        except Exception as e:
            all_scans.append(f"=== {description} ===\nError: {str(e)}\n")
    
    combined_output = "\n".join(all_scans)
    
    print("Sending to Claude for analysis...")
    
    # Send to Claude
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        messages=[{
            "role": "user",
            "content": f"""You are a cybersecurity analyst scanning a small business network. Analyze these security scans from multiple machines:

{combined_output}

Provide:
1. **Network Overview**: What services are running across the network
2. **Top 3 Critical Vulnerabilities**: Prioritized by actual risk
3. **Risk Assessment**: Overall security posture (High/Medium/Low risk)
4. **Remediation Steps**: Specific actions to take

Be concise but actionable. Format with clear headers."""
        }]
    )
    
    return {
        "raw_output": combined_output,
        "ai_analysis": message.content[0].text,
        "targets_scanned": len(targets)
    }

@app.get("/")
async def root():
    return {"status": "CyberSec AI Agent API running", "version": "1.0"}

@app.get("/health")
async def health():
    return {"status": "healthy"}
