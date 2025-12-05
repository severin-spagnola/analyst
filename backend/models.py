from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel
from enum import Enum

class ScanStatus(str, Enum):
    IN_PROGRESS = "In Progress"
    COMPLETED = "Completed"
    CLEAN = "Clean"
    FAILED = "Failed"

class Tool(str, Enum):
    NMAP = "Nmap"
    NUCLEI = "Nuclei"
    NIKTO = "Nikto"
    OPENVAS = "OpenVAS"

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class FindingStatus(str, Enum):
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"

class Scan(BaseModel):
    id: str
    target: str
    tools: List[Tool]
    startedAt: str  # ISO timestamp
    status: ScanStatus
    issues: int
    critical: int
    durationMinutes: Optional[int] = None
    owner: str = "system"
    riskScore: int  # 0-100
    summary: str
    aiSummary: str

class Finding(BaseModel):
    id: str
    scanId: str
    host: str
    port: Optional[int] = None
    service: Optional[str] = None
    severity: Severity
    tool: Tool
    status: FindingStatus
    title: str
    description: str
    recommendation: str

class ChatMessage(BaseModel):
    id: str
    sender: str  # "user" or "ai"
    text: str
    time: str  # e.g., "2 mins ago"

class StartScanRequest(BaseModel):
    target: str
    tools: List[Tool]

class ChatRequest(BaseModel):
    prompt: str
    scanId: Optional[str] = None