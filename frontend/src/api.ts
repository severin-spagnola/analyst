const API_BASE = 'http://localhost:8000/api';

export interface Scan {
  id: string;
  target: string;
  tools: string[];
  startedAt: string;
  status: 'In Progress' | 'Completed' | 'Clean' | 'Failed';
  issues: number;
  critical: number;
  durationMinutes?: number;
  owner: string;
  riskScore: number;
  summary: string;
  aiSummary: string;
}

export interface Finding {
  id: string;
  scanId: string;
  host: string;
  port?: number;
  service?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  tool: string;
  status: 'Open' | 'In Progress' | 'Resolved';
  title: string;
  description: string;
  recommendation: string;
}

export interface ChatMessage {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  time: string;
}

// Replace mock functions with real API calls
export async function fetchScans(): Promise<Scan[]> {
  const response = await fetch(`${API_BASE}/scans`);
  const data = await response.json();
  return data.scans;
}

export async function fetchFindings(): Promise<Finding[]> {
  const response = await fetch(`${API_BASE}/findings`);
  const data = await response.json();
  return data.findings;
}

export async function startScan(tools: string[], target: string): Promise<Scan> {
  const response = await fetch(`${API_BASE}/scans/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tools, target })
  });
  const data = await response.json();
  return data.scan;
}

export async function cancelScan(scanId: string): Promise<void> {
  await fetch(`${API_BASE}/scans/${scanId}/cancel`, {
    method: 'POST'
  });
}

export async function sendChat(prompt: string, scanId?: string): Promise<ChatMessage> {
  const response = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt, scanId })
  });
  const data = await response.json();
  return data.message;
}