from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import anthropic
import os
from dotenv import load_dotenv
import uuid
from datetime import datetime, timedelta
import asyncio
from typing import Dict, List
from models import (
    Scan, Finding, ChatMessage, StartScanRequest, ChatRequest,
    ScanStatus, Tool, Severity, FindingStatus
)

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

# In-memory storage (replace with DB in production)
scans_db: Dict[str, Scan] = {}
findings_db: Dict[str, Finding] = {}
active_scans: Dict[str, bool] = {}  # Track cancellations

# Initialize with some mock data
def init_mock_data():
    # Mock scan 1
    scan1_id = str(uuid.uuid4())
    scans_db[scan1_id] = Scan(
        id=scan1_id,
        target="prod-api.internal",
        tools=[Tool.NMAP, Tool.NUCLEI],
        startedAt=(datetime.now() - timedelta(hours=2)).isoformat(),
        status=ScanStatus.COMPLETED,
        issues=7,
        critical=2,
        durationMinutes=15,
        riskScore=78,
        summary="AI flagged 2 critical paths: outdated OpenSSH on port 22 and exposed admin dashboard on 8443.",
        aiSummary="Found critical SSH vulnerability (CVE-2023-xxxx) and exposed admin panel. Immediate patching required."
    )
    
    # Mock findings for scan1
    findings_db[str(uuid.uuid4())] = Finding(
        id=str(uuid.uuid4()),
        scanId=scan1_id,
        host="prod-api.internal",
        port=22,
        service="SSH",
        severity=Severity.CRITICAL,
        tool=Tool.NMAP,
        status=FindingStatus.OPEN,
        title="Outdated OpenSSH Version",
        description="OpenSSH 7.4 detected with known vulnerabilities",
        recommendation="Update to OpenSSH 9.0 or later: apt-get update && apt-get install openssh-server"
    )
    
    findings_db[str(uuid.uuid4())] = Finding(
        id=str(uuid.uuid4()),
        scanId=scan1_id,
        host="prod-api.internal",
        port=8443,
        service="HTTPS",
        severity=Severity.CRITICAL,
        tool=Tool.NUCLEI,
        status=FindingStatus.OPEN,
        title="Exposed Admin Dashboard",
        description="Admin panel accessible without VPN at /admin with default credentials",
        recommendation="Restrict access to VPN-only networks and enforce strong authentication"
    )
    
    # Mock scan 2
    scan2_id = str(uuid.uuid4())
    scans_db[scan2_id] = Scan(
        id=scan2_id,
        target="payments.edge",
        tools=[Tool.NIKTO, Tool.OPENVAS],
        startedAt=(datetime.now() - timedelta(days=1)).isoformat(),
        status=ScanStatus.COMPLETED,
        issues=4,
        critical=1,
        durationMinutes=22,
        riskScore=71,
        summary="Directory listing enabled on /reports; outdated TLS ciphers.",
        aiSummary="Payments service has weak TLS configuration and directory traversal vulnerability. Focus on hardening SSH and closing admin access."
    )
    
    # Mock scan 3 - Clean
    scan3_id = str(uuid.uuid4())
    scans_db[scan3_id] = Scan(
        id=scan3_id,
        target="staging.api",
        tools=[Tool.NMAP, Tool.NIKTO, Tool.NUCLEI],
        startedAt=(datetime.now() - timedelta(hours=5)).isoformat(),
        status=ScanStatus.CLEAN,
        issues=0,
        critical=0,
        durationMinutes=18,
        riskScore=12,
        summary="No exploitable issues found across probed services.",
        aiSummary="Staging environment is well-configured with no critical vulnerabilities detected."
    )

init_mock_data()

@app.get("/api/scans")
async def get_scans():
    """Fetch all scans"""
    return {"scans": list(scans_db.values())}

@app.get("/api/findings")
async def get_findings():
    """Fetch all findings"""
    return {"findings": list(findings_db.values())}

@app.post("/api/scans/start")
async def start_scan(request: StartScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan"""
    scan_id = str(uuid.uuid4())
    
    # Create initial scan object
    scan = Scan(
        id=scan_id,
        target=request.target,
        tools=request.tools,
        startedAt=datetime.now().isoformat(),
        status=ScanStatus.IN_PROGRESS,
        issues=0,
        critical=0,
        durationMinutes=None,
        riskScore=0,
        summary="Scan in progress...",
        aiSummary="Running security analysis..."
    )
    
    scans_db[scan_id] = scan
    active_scans[scan_id] = True
    
    # Run scan in background
    background_tasks.add_task(run_scan, scan_id, request.target, request.tools)
    
    return {"scan": scan}

async def run_scan(scan_id: str, target: str, tools: List[Tool]):
    """Background task to actually run the scan"""
    print(f"\n=== STARTING SCAN {scan_id} ===")
    print(f"Target: {target}")
    print(f"Tools: {tools}")
    
    start_time = datetime.now()
    
    try:
        all_output = []
        
        # Run each tool
        for tool in tools:
            print(f"\n--- Running {tool} on {target} ---")
            
            if not active_scans.get(scan_id, False):
                print(f"Scan {scan_id} was cancelled")
                scans_db[scan_id].status = ScanStatus.FAILED
                scans_db[scan_id].summary = "Scan cancelled by user"
                scans_db[scan_id].aiSummary = "Scan was cancelled before completion"
                return
            
            if tool == Tool.NMAP:
                print(f"Running nmap -sV -F {target}...")
                result = subprocess.run(
                    ['nmap', '-sV', '-F', target],
                    capture_output=True,
                    text=True,
                    timeout=45
                )
                print(f"Nmap completed. Output length: {len(result.stdout)} chars")
                all_output.append(f"=== NMAP ===\n{result.stdout}")
            
            elif tool == Tool.NIKTO:
                print(f"Running nikto on {target}...")
                result = subprocess.run(
                    ['nikto', '-h', target, '-Tuning', '1,2,3'],
                    capture_output=True,
                    text=True,
                    timeout=45
                )
                print(f"Nikto completed. Output length: {len(result.stdout)} chars")
                all_output.append(f"=== NIKTO ===\n{result.stdout}")
            
            # Nuclei and OpenVAS would go here
            elif tool == Tool.NUCLEI:
                print(f"Nuclei not implemented yet, skipping...")
                all_output.append(f"=== NUCLEI ===\nNot implemented yet")
            
            elif tool == Tool.OPENVAS:
                print(f"OpenVAS not implemented yet, skipping...")
                all_output.append(f"=== OPENVAS ===\nNot implemented yet")
        
        combined_output = "\n\n".join(all_output)
        print(f"\n--- Sending to Claude for analysis ---")
        print(f"Total output length: {len(combined_output)} chars")
        
        # Get AI analysis
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{
                "role": "user",
                "content": f"""Analyze this security scan for {target}:

{combined_output}

Provide:
1. Issue count (estimate total vulnerabilities found)
2. Critical issue count
3. Risk score (0-100, where 100 is most dangerous)
4. Brief summary (1-2 sentences for table display)
5. Detailed AI summary (2-3 sentences for analysis)

Format as:
ISSUES: <number>
CRITICAL: <number>
RISK_SCORE: <number>
SUMMARY: <text>
AI_SUMMARY: <text>"""
            }]
        )
        
        response_text = message.content[0].text
        print(f"\n--- Claude response ---")
        print(response_text)
        
        # Parse AI response
        issues = 0
        critical = 0
        risk_score = 50
        summary = "Analysis complete"
        ai_summary = "Security scan completed"
        
        for line in response_text.split('\n'):
            if line.startswith('ISSUES:'):
                issues = int(line.split(':')[1].strip())
            elif line.startswith('CRITICAL:'):
                critical = int(line.split(':')[1].strip())
            elif line.startswith('RISK_SCORE:'):
                risk_score = int(line.split(':')[1].strip())
            elif line.startswith('SUMMARY:'):
                summary = line.split(':', 1)[1].strip()
            elif line.startswith('AI_SUMMARY:'):
                ai_summary = line.split(':', 1)[1].strip()
        
        # Update scan
        duration = (datetime.now() - start_time).seconds // 60
        print(f"\n--- Updating scan results ---")
        print(f"Issues: {issues}, Critical: {critical}, Risk: {risk_score}%")
        
        scans_db[scan_id].status = ScanStatus.COMPLETED if issues > 0 else ScanStatus.CLEAN
        scans_db[scan_id].issues = issues
        scans_db[scan_id].critical = critical
        scans_db[scan_id].durationMinutes = duration
        scans_db[scan_id].riskScore = risk_score
        scans_db[scan_id].summary = summary
        scans_db[scan_id].aiSummary = ai_summary
        
        print(f"=== SCAN {scan_id} COMPLETED ===\n")
        
        # Create sample finding if issues found
        if issues > 0:
            finding_id = str(uuid.uuid4())
            findings_db[finding_id] = Finding(
                id=finding_id,
                scanId=scan_id,
                host=target,
                port=80,
                service="HTTP",
                severity=Severity.CRITICAL if critical > 0 else Severity.HIGH,
                tool=tools[0],
                status=FindingStatus.OPEN,
                title=f"Security issue detected on {target}",
                description=summary,
                recommendation="Review scan details and apply recommended patches"
            )
    
    except Exception as e:
        print(f"\n!!! SCAN {scan_id} FAILED !!!")
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        scans_db[scan_id].status = ScanStatus.FAILED
        scans_db[scan_id].summary = f"Scan failed: {str(e)}"
        scans_db[scan_id].aiSummary = f"Error during scan: {str(e)}"
    
    finally:
        active_scans[scan_id] = False

@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel an in-progress scan"""
    if scan_id in active_scans:
        active_scans[scan_id] = False
    
    if scan_id in scans_db:
        scans_db[scan_id].status = ScanStatus.FAILED
        scans_db[scan_id].summary = "Scan cancelled by user"
        scans_db[scan_id].aiSummary = "Scan was cancelled before completion"
    
    return {"success": True}

@app.post("/api/chat")
async def chat(request: ChatRequest):
    """AI Assistant chat endpoint"""
    try:
        # Get scan context if provided
        context = ""
        if request.scanId and request.scanId in scans_db:
            scan = scans_db[request.scanId]
            context = f"\nContext - Current Scan: {scan.target}, Status: {scan.status}, Issues: {scan.issues}, Risk: {scan.riskScore}%, Summary: {scan.aiSummary}"
        
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{
                "role": "user",
                "content": f"""You are a cybersecurity AI assistant helping analyze security scans.{context}

User question: {request.prompt}

Provide a helpful, concise response focused on security recommendations."""
            }]
        )
        
        response_text = message.content[0].text
        
        return {
            "message": ChatMessage(
                id=str(uuid.uuid4()),
                sender="ai",
                text=response_text,
                time="Just now"
            )
        }
    
    except Exception as e:
        return {
            "message": ChatMessage(
                id=str(uuid.uuid4()),
                sender="ai",
                text=f"Sorry, I encountered an error: {str(e)}",
                time="Just now"
            )
        }

@app.get("/")
async def root():
    return {"status": "Recon Copilot API running", "version": "2.0"}

@app.get("/health")
async def health():
    return {"status": "healthy"}


# scanme.nmap.org     # Best option - public test server
# localhost           # Will scan your machine
# 127.0.0.1          # Same as localhost
# google.com         # Will work but limited info