import { useState, useEffect } from 'react';
import { fetchScans, fetchFindings, startScan, cancelScan, sendChat } from './api';
import type { Scan, Finding, ChatMessage, ScanTool, ScanStatus, Severity, FindingStatus } from './types';

type View = 'landing' | 'dashboard';
type Tab = 'scans' | 'findings' | 'analytics' | 'assistant';
type ScanFilter = 'All' | 'Issues' | 'Clean' | 'Failed';

function App() {
  // View state
  const [view, setView] = useState<View>('landing');
  const [activeTab, setActiveTab] = useState<Tab>('scans');

  // Data state
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loadingData, setLoadingData] = useState(true);

  // Scans tab state
  const [target, setTarget] = useState('prod-edge.internal');
  const [selectedTools, setSelectedTools] = useState<ScanTool[]>(['Nmap', 'Nuclei']);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [scanFilter, setScanFilter] = useState<ScanFilter>('All');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  // Chat state
  const [chatInput, setChatInput] = useState('');
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      id: 'init-ai',
      sender: 'ai',
      text: "Hi! I can summarize scans, craft mitigations, or prep exec briefs. Pick a scan to start.",
      time: '5m ago',
    },
    {
      id: 'init-user',
      sender: 'user',
      text: 'Give me a quick executive summary of the latest findings.',
      time: '4m ago',
    },
  ]);
  const [sendingMessage, setSendingMessage] = useState(false);

  // Load initial data
  useEffect(() => {
    const loadInitialData = async () => {
      try {
        const [scansData, findingsData] = await Promise.all([
          fetchScans(),
          fetchFindings(),
        ]);
        
        // Sort scans by date, newest first
        const sortedScans = scansData.sort((a, b) => 
          new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
        );
        
        setScans(sortedScans);
        setFindings(findingsData);
        
        if (sortedScans.length > 0) {
          setSelectedScanId(sortedScans[0].id);
        }
      } catch (error) {
        console.error('Failed to load data:', error);
      } finally {
        setLoadingData(false);
      }
    };

    loadInitialData();
  }, []);

  // Progress bar simulation
  useEffect(() => {
    if (!scanning) return;
    
    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 95) return Math.min(prev + 0.5, 98);
        if (prev >= 80) return prev + 1;
        if (prev >= 60) return prev + 2;
        return prev + 3;
      });
    }, 500);
    
    return () => clearInterval(interval);
  }, [scanning]);

  // Poll for scan updates while scanning
  useEffect(() => {
    if (!scanning || !selectedScanId) return;
    
    console.log('Starting poll for scan:', selectedScanId);
    
    const interval = setInterval(async () => {
      try {
        const scansData = await fetchScans();
        setScans(scansData.sort((a, b) => 
          new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
        ));
        
        const currentScan = scansData.find((s) => s.id === selectedScanId);
        
        if (currentScan) {
          console.log('Poll update:', currentScan.status, currentScan.riskScore + '%');
          
          if (currentScan.status !== 'In Progress') {
            console.log('Scan completed!', currentScan);
            setProgress(100);
            
            const findingsData = await fetchFindings();
            setFindings(findingsData);
            
            setTimeout(() => {
              setScanning(false);
              setProgress(0);
            }, 1500);
          }
        }
      } catch (error) {
        console.error('Poll failed:', error);
      }
    }, 2000);
    
    return () => {
      console.log('Stopping poll');
      clearInterval(interval);
    };
  }, [scanning, selectedScanId]);

  // Handle start scan
  const handleStartScan = async () => {
    setProgress(0);
    setScanning(true);

    try {
      console.log('Starting scan with tools:', selectedTools, 'target:', target);
      
      // Call real backend API
      const newScan = await startScan(selectedTools, target);
      
      console.log('Backend returned scan:', newScan);
      
      // Add to local state with backend's ID
      setScans((prev) => [newScan, ...prev]);
      setSelectedScanId(newScan.id);
      
    } catch (error) {
      console.error('Failed to start scan:', error);
      setScanning(false);
      alert('Failed to start scan: ' + error);
    }
  };

  // Handle cancel scan
  const handleCancelScan = async () => {
    if (!selectedScanId) return;
    
    setScanning(false);
    setProgress(0);
    
    try {
      await cancelScan(selectedScanId);
      
      setScans((prev) =>
        prev.map((s) =>
          s.id === selectedScanId
            ? {
                ...s,
                status: 'Failed' as const,
                summary: 'Scan cancelled by user',
                aiSummary: 'This scan was cancelled before completion.',
              }
            : s
        )
      );
    } catch (error) {
      console.error('Cancel failed:', error);
    }
  };

  // Handle send chat
  const handleSendChat = async () => {
    if (!chatInput.trim()) return;

    const userMsg: ChatMessage = {
      id: `msg-${Date.now()}`,
      sender: 'user',
      text: chatInput,
      time: 'Just now',
    };

    setChatMessages((prev) => [...prev, userMsg]);
    setChatInput('');
    setSendingMessage(true);

    try {
      const aiMessage = await sendChat(chatInput, selectedScanId || undefined);
      setChatMessages((prev) => [...prev, aiMessage]);
    } catch (error) {
      console.error('Chat failed:', error);
      const errorMsg: ChatMessage = {
        id: `msg-${Date.now()}`,
        sender: 'ai',
        text: 'Sorry, I encountered an error. Please try again.',
        time: 'Just now',
      };
      setChatMessages((prev) => [...prev, errorMsg]);
    } finally {
      setSendingMessage(false);
    }
  };

  // Computed values
  const filteredScans = scans.filter((s) => {
    if (scanFilter === 'All') return true;
    if (scanFilter === 'Issues') return s.issues > 0 || s.critical > 0;
    if (scanFilter === 'Clean') return s.status === 'Clean';
    if (scanFilter === 'Failed') return s.status === 'Failed';
    return true;
  });

  const selectedScan = scans.find((s) => s.id === selectedScanId);

  const totalScans = scans.length;
  const highCriticalFindings = findings.filter(
    (f) => f.severity === 'Critical' || f.severity === 'High'
  ).length;
  const uniqueTools = Array.from(new Set(scans.flatMap((s) => s.tools))).length;
  const overallRisk = scans.length > 0
    ? Math.round(scans.reduce((sum, s) => sum + s.riskScore, 0) / scans.length)
    : 0;

  // Group findings by host
  const findingsByHost = findings.reduce((acc, f) => {
    if (!acc[f.host]) acc[f.host] = [];
    acc[f.host].push(f);
    return acc;
  }, {} as Record<string, Finding[]>);

  // Analytics data
  const findingsBySeverity = {
    Critical: findings.filter((f) => f.severity === 'Critical').length,
    High: findings.filter((f) => f.severity === 'High').length,
    Medium: findings.filter((f) => f.severity === 'Medium').length,
    Low: findings.filter((f) => f.severity === 'Low').length,
    Info: findings.filter((f) => f.severity === 'Info').length,
  };
  const maxSeverityCount = Math.max(...Object.values(findingsBySeverity), 1);

  const findingsByTool = {
    Nmap: findings.filter((f) => f.tool === 'Nmap').length,
    Nuclei: findings.filter((f) => f.tool === 'Nuclei').length,
    Nikto: findings.filter((f) => f.tool === 'Nikto').length,
    OpenVAS: findings.filter((f) => f.tool === 'OpenVAS').length,
  };
  const maxToolCount = Math.max(...Object.values(findingsByTool), 1);

  // Landing page
  if (view === 'landing') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-100 flex flex-col items-center justify-center p-6">
        <div className="max-w-4xl w-full space-y-8">
          {/* Hero */}
          <div className="text-center space-y-4">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-sm mb-4">
              <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              New
            </div>
            <h1 className="text-5xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Recon Copilot
            </h1>
            <p className="text-xl text-slate-400 max-w-2xl mx-auto">
              AI-powered recon & vulnerability dashboard. Merge Nmap, Nuclei, Nikto, and OpenVAS into one clear storyline.
            </p>
            <div className="flex gap-4 justify-center pt-4">
              <button
                onClick={() => setView('dashboard')}
                className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg font-medium hover:from-cyan-400 hover:to-blue-500 transition-all"
              >
                Go to Dashboard
              </button>
              <button className="px-6 py-3 bg-slate-800 rounded-lg font-medium hover:bg-slate-700 transition-all border border-slate-700">
                Learn More
              </button>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-8">
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-4 space-y-2">
              <div className="text-slate-400 text-sm">Targets Watched</div>
              <div className="text-3xl font-bold text-cyan-400">28</div>
            </div>
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-4 space-y-2">
              <div className="text-slate-400 text-sm">Criticals</div>
              <div className="text-3xl font-bold text-red-400">6</div>
            </div>
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-4 space-y-2">
              <div className="text-slate-400 text-sm">Avg SLA</div>
              <div className="text-3xl font-bold text-slate-100">14h</div>
            </div>
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-4 space-y-2">
              <div className="text-slate-400 text-sm">Tools</div>
              <div className="text-3xl font-bold text-slate-100">4</div>
            </div>
          </div>

          {/* Features */}
          <div className="grid md:grid-cols-3 gap-4 pt-4">
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-6 space-y-3">
              <div className="w-10 h-10 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                <div className="w-2 h-2 rounded-full bg-purple-400" />
              </div>
              <h3 className="font-semibold text-lg">Multi-tool scans</h3>
              <p className="text-slate-400 text-sm">
                Blend Nmap, Nuclei, Nikto, and OpenVAS findings into one pane.
              </p>
            </div>
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-6 space-y-3">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                <div className="w-2 h-2 rounded-full bg-cyan-400" />
              </div>
              <h3 className="font-semibold text-lg">AI risk summaries</h3>
              <p className="text-slate-400 text-sm">
                Get concise AI briefings per host with prioritized remediation.
              </p>
            </div>
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-6 space-y-3">
              <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                <div className="w-2 h-2 rounded-full bg-blue-400" />
              </div>
              <h3 className="font-semibold text-lg">Plugin-based design</h3>
              <p className="text-slate-400 text-sm">
                Swap scanners or add new ones without touching the UI.
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Dashboard
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                <div className="w-3 h-3 rounded-full bg-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold">RECON COPILOT</h1>
                <p className="text-xs text-slate-400">AI recon & vulnerability dashboard</p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span>Logged in as</span>
              <span className="text-cyan-400 font-medium">Ava Ops</span>
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600" />
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        {/* Metrics */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-4 space-y-2">
            <div className="flex items-center gap-2">
              <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
                <div className="w-3 h-3 rounded-full bg-blue-400" />
              </div>
              <div className="flex-1">
                <div className="text-sm text-slate-400">TOTAL SCANS</div>
                <div className="text-2xl font-bold">{totalScans}</div>
                <div className="text-xs text-slate-500">Last 30 days</div>
              </div>
            </div>
          </div>

          <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-4 space-y-2">
            <div className="flex items-center gap-2">
              <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                <div className="w-3 h-3 rounded-full bg-red-400" />
              </div>
              <div className="flex-1">
                <div className="text-sm text-slate-400">HIGH/CRITICAL ISSUES</div>
                <div className="text-2xl font-bold">{highCriticalFindings}</div>
                <div className="text-xs text-slate-500">Across all hosts</div>
              </div>
            </div>
          </div>

          <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-4 space-y-2">
            <div className="flex items-center gap-2">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                <div className="w-3 h-3 rounded-full bg-cyan-400" />
              </div>
              <div className="flex-1">
                <div className="text-sm text-slate-400">TOOLS USED</div>
                <div className="text-2xl font-bold">{uniqueTools}</div>
                <div className="text-xs text-slate-500">Nmap, Nuclei, Nikto, OpenVAS</div>
              </div>
            </div>
          </div>

          <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-4 space-y-2">
            <div className="flex items-center gap-2">
              <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
                <div className="w-3 h-3 rounded-full bg-purple-400" />
              </div>
              <div className="flex-1">
                <div className="text-sm text-slate-400">OVERALL RISK SCORE</div>
                <div className="text-2xl font-bold">{overallRisk}%</div>
                <div className="text-xs text-slate-500">Weighted by severity</div>
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-2 mb-6">
          <button
            onClick={() => setActiveTab('scans')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeTab === 'scans'
                ? 'bg-slate-800 text-cyan-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Scans
          </button>
          <button
            onClick={() => setActiveTab('findings')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeTab === 'findings'
                ? 'bg-slate-800 text-cyan-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Security Findings
          </button>
          <button
            onClick={() => setActiveTab('analytics')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeTab === 'analytics'
                ? 'bg-slate-800 text-cyan-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Analytics
          </button>
          <button
            onClick={() => setActiveTab('assistant')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeTab === 'assistant'
                ? 'bg-slate-800 text-cyan-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            AI Assistant
          </button>
          <div className="flex-1" />
          <button
            onClick={() => setActiveTab('assistant')}
            className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg font-medium hover:from-cyan-400 hover:to-blue-500 transition-all"
          >
            Open AI assistant
          </button>
        </div>

        {/* Scans Tab */}
        {activeTab === 'scans' && (
          <div className="space-y-6">
            {/* Scan Controls */}
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold">Scans</h2>
                <div className="text-sm text-slate-400">
                  Kick off a new scan or review the latest runs.
                </div>
              </div>

              <div className="flex gap-2">
                {(['Nmap', 'Nuclei', 'Nikto', 'OpenVAS'] as ScanTool[]).map((tool) => (
                  <button
                    key={tool}
                    onClick={() =>
                      setSelectedTools((prev) =>
                        prev.includes(tool)
                          ? prev.filter((t) => t !== tool)
                          : [...prev, tool]
                      )
                    }
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                      selectedTools.includes(tool)
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'
                    }`}
                  >
                    {tool}
                  </button>
                ))}
              </div>

              <div className="flex gap-2">
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="prod-edge.internal"
                  className="flex-1 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
                {scanning ? (
                  <button
                    onClick={handleCancelScan}
                    className="px-6 py-2 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg font-medium hover:bg-red-500/30 transition-all"
                  >
                    Cancel
                  </button>
                ) : (
                  <button
                    onClick={handleStartScan}
                    className="px-6 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg font-medium hover:from-cyan-400 hover:to-blue-500 transition-all"
                  >
                    New Scan
                  </button>
                )}
              </div>

              {scanning && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-400">Scanning...</span>
                    <span className="text-cyan-400">{Math.round(progress)}%</span>
                  </div>
                  <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-cyan-500 to-blue-600 transition-all duration-300"
                      style={{ width: `${progress}%` }}
                    />
                  </div>
                </div>
              )}

              {/* Filters */}
              <div className="flex gap-2">
                {(['All', 'Issues', 'Clean', 'Failed'] as ScanFilter[]).map((filter) => (
                  <button
                    key={filter}
                    onClick={() => setScanFilter(filter)}
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                      scanFilter === filter
                        ? 'bg-slate-800 text-slate-100'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {filter}
                  </button>
                ))}
              </div>
            </div>

            {/* Scan List */}
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl overflow-hidden">
              <div className="grid grid-cols-[2fr,1.5fr,1fr,1fr,2fr] gap-4 px-6 py-3 border-b border-slate-800 text-sm font-medium text-slate-400">
                <div>TARGET</div>
                <div>TOOLS</div>
                <div>ISSUES</div>
                <div>STATUS</div>
                <div>RISK</div>
              </div>

              {loadingData ? (
                <div className="p-12 text-center text-slate-400">
                  Loading scans...
                </div>
              ) : filteredScans.length === 0 ? (
                <div className="p-12 text-center text-slate-400">
                  No scans match the current filter
                </div>
              ) : (
                <div className="divide-y divide-slate-800">
                  {filteredScans.map((scan) => (
                    <button
                      key={scan.id}
                      onClick={() => setSelectedScanId(scan.id)}
                      className={`w-full grid grid-cols-[2fr,1.5fr,1fr,1fr,2fr] gap-4 px-6 py-4 hover:bg-slate-800/50 transition-all text-left ${
                        selectedScanId === scan.id ? 'bg-slate-800/50' : ''
                      }`}
                    >
                      <div>
                        <div className="font-medium">{scan.target}</div>
                        <div className="text-xs text-slate-500">
                          {new Date(scan.startedAt).toLocaleString()}
                        </div>
                      </div>
                      <div className="flex gap-1.5 flex-wrap">
                        {scan.tools.map((tool) => (
                          <span
                            key={tool}
                            className="px-2 py-0.5 rounded bg-slate-800 text-xs"
                          >
                            {tool}
                          </span>
                        ))}
                      </div>
                      <div>
                        <div className="font-medium">{scan.issues} issues</div>
                        {scan.critical > 0 && (
                          <div className="text-xs text-red-400">{scan.critical} critical</div>
                        )}
                      </div>
                      <div>
                        <span
                          className={`px-2 py-1 rounded-lg text-xs font-medium ${
                            scan.status === 'Completed'
                              ? 'bg-green-500/10 text-green-400'
                              : scan.status === 'Clean'
                              ? 'bg-blue-500/10 text-blue-400'
                              : scan.status === 'Failed'
                              ? 'bg-red-500/10 text-red-400'
                              : 'bg-yellow-500/10 text-yellow-400'
                          }`}
                        >
                          {scan.status}
                        </span>
                      </div>
                      <div>
                        <div className={`font-mono text-sm font-bold ${
                          scan.riskScore > 70 ? 'text-red-400' : 
                          scan.riskScore > 40 ? 'text-yellow-400' : 
                          'text-green-400'
                        }`}>
                          {scan.riskScore}%
                        </div>
                        <div className="text-xs text-slate-400 line-clamp-1">
                          {scan.summary}
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Selected Scan Detail */}
            {selectedScan && (
              <div className="grid grid-cols-2 gap-6">
                <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-6 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="font-bold">Selected scan</h3>
                    <button className="px-3 py-1 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded-lg text-sm font-medium">
                      AI Summary
                    </button>
                  </div>
                  <div className="text-sm text-slate-400">
                    AI summary for the latest run.
                  </div>
                  <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 space-y-3">
                    <div className="font-medium text-slate-200">SUMMARY</div>
                    <div className="text-sm text-slate-300">{selectedScan.aiSummary}</div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1">
                      <div className="text-xs text-slate-400">Issues</div>
                      <div className="text-2xl font-bold">{selectedScan.issues}</div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-xs text-slate-400">Risk</div>
                      <div className="text-2xl font-bold">{selectedScan.riskScore}%</div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Findings Tab */}
        {activeTab === 'findings' && (
          <div className="space-y-6">
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-6">
              <h2 className="text-xl font-bold mb-4">Security Findings</h2>

              {Object.entries(findingsByHost).map(([host, hostFindings]) => {
                const criticalCount = hostFindings.filter((f) => f.severity === 'Critical').length;
                const highCount = hostFindings.filter((f) => f.severity === 'High').length;
                const mediumCount = hostFindings.filter((f) => f.severity === 'Medium').length;

                return (
                  <details key={host} className="group mb-4">
                    <summary className="cursor-pointer list-none">
                      <div className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg hover:bg-slate-800 transition-all">
                        <div className="flex items-center gap-3">
                          <div className="text-sm font-medium">{host}</div>
                          <div className="flex gap-2">
                            {criticalCount > 0 && (
                              <span className="px-2 py-0.5 bg-red-500/10 text-red-400 rounded text-xs">
                                {criticalCount} Critical
                              </span>
                            )}
                            {highCount > 0 && (
                              <span className="px-2 py-0.5 bg-orange-500/10 text-orange-400 rounded text-xs">
                                {highCount} High
                              </span>
                            )}
                            {mediumCount > 0 && (
                              <span className="px-2 py-0.5 bg-yellow-500/10 text-yellow-400 rounded text-xs">
                                {mediumCount} Medium
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="text-sm text-slate-400">View details →</div>
                      </div>
                    </summary>

                    <div className="mt-2 space-y-2 pl-4">
                      {hostFindings.map((finding) => (
                        <div
                          key={finding.id}
                          className="bg-slate-800/30 border border-slate-700 rounded-lg p-4 space-y-2"
                        >
                          <div className="flex items-start justify-between">
                            <div className="flex items-center gap-2">
                              <span
                                className={`px-2 py-0.5 rounded text-xs font-medium ${
                                  finding.severity === 'Critical'
                                    ? 'bg-red-500/10 text-red-400'
                                    : finding.severity === 'High'
                                    ? 'bg-orange-500/10 text-orange-400'
                                    : finding.severity === 'Medium'
                                    ? 'bg-yellow-500/10 text-yellow-400'
                                    : 'bg-blue-500/10 text-blue-400'
                                }`}
                              >
                                {finding.severity}
                              </span>
                              <span className="text-xs text-slate-500">{finding.tool}</span>
                              {finding.port && (
                                <span className="text-xs text-slate-500">:{finding.port}</span>
                              )}
                              {finding.service && (
                                <span className="text-xs text-slate-500">({finding.service})</span>
                              )}
                            </div>
                            <span
                              className={`px-2 py-0.5 rounded text-xs ${
                                finding.status === 'Open'
                                  ? 'bg-red-500/10 text-red-400'
                                  : finding.status === 'In Progress'
                                  ? 'bg-yellow-500/10 text-yellow-400'
                                  : 'bg-green-500/10 text-green-400'
                              }`}
                            >
                              {finding.status}
                            </span>
                          </div>
                          <div className="font-medium text-sm">{finding.title}</div>
                          <div className="text-sm text-slate-400">{finding.description}</div>
                          <div className="text-sm text-cyan-400 bg-cyan-500/5 border border-cyan-500/10 rounded p-2">
                            <span className="font-medium">Recommendation:</span> {finding.recommendation}
                          </div>
                        </div>
                      ))}
                    </div>
                  </details>
                );
              })}
            </div>
          </div>
        )}

        {/* Analytics Tab */}
        {activeTab === 'analytics' && (
          <div className="space-y-6">
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-6">
              <h2 className="text-xl font-bold mb-6">Analytics</h2>

              <div className="space-y-8">
                {/* By Severity */}
                <div>
                  <h3 className="font-medium mb-4 text-slate-300">Findings by Severity</h3>
                  <div className="space-y-3">
                    {Object.entries(findingsBySeverity).map(([severity, count]) => (
                      <div key={severity} className="space-y-1">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-slate-400">{severity}</span>
                          <span className="font-medium">{count}</span>
                        </div>
                        <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              severity === 'Critical'
                                ? 'bg-red-500'
                                : severity === 'High'
                                ? 'bg-orange-500'
                                : severity === 'Medium'
                                ? 'bg-yellow-500'
                                : 'bg-blue-500'
                            }`}
                            style={{ width: `${(count / maxSeverityCount) * 100}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* By Tool */}
                <div>
                  <h3 className="font-medium mb-4 text-slate-300">Findings by Tool</h3>
                  <div className="space-y-3">
                    {Object.entries(findingsByTool).map(([tool, count]) => (
                      <div key={tool} className="space-y-1">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-slate-400">{tool}</span>
                          <span className="font-medium">{count}</span>
                        </div>
                        <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-cyan-500"
                            style={{ width: `${(count / maxToolCount) * 100}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Assistant Tab */}
        {activeTab === 'assistant' && (
          <div className="grid grid-cols-2 gap-6">
            {/* Left Panel */}
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="font-bold">Selected scan</h3>
                <select
                  value={selectedScanId || ''}
                  onChange={(e) => setSelectedScanId(e.target.value)}
                  className="px-3 py-1 bg-slate-800 border border-slate-700 rounded text-sm"
                >
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.target}
                    </option>
                  ))}
                </select>
              </div>

              {selectedScan && (
                <>
                  <div className="text-sm text-slate-400">AI summary for the latest run.</div>
                  <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 space-y-3">
                    <div className="text-sm text-slate-300">{selectedScan.aiSummary}</div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1">
                      <div className="text-xs text-slate-400">Issues</div>
                      <div className="text-2xl font-bold">{selectedScan.issues}</div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-xs text-slate-400">Risk</div>
                      <div className="text-2xl font-bold">{selectedScan.riskScore}%</div>
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* Right Panel - Chat */}
            <div className="bg-slate-900/50 backdrop-blur border border-slate-800 rounded-xl p-6 flex flex-col h-[600px]">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-bold">AI Assistant</h3>
                <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              </div>
              <div className="text-sm text-slate-400 mb-4">
                Ask the AI to summarize or suggest mitigations.
              </div>

              {/* Messages */}
              <div className="flex-1 overflow-y-auto space-y-4 mb-4">
                {chatMessages.map((msg) => (
                  <div
                    key={msg.id}
                    className={`flex gap-3 ${msg.sender === 'user' ? 'flex-row-reverse' : ''}`}
                  >
                    <div
                      className={`w-8 h-8 rounded-full flex-shrink-0 ${
                        msg.sender === 'ai'
                          ? 'bg-gradient-to-br from-cyan-500 to-blue-600'
                          : 'bg-slate-700'
                      }`}
                    />
                    <div className="flex-1 space-y-1">
                      <div
                        className={`px-4 py-2 rounded-lg text-sm ${
                          msg.sender === 'ai'
                            ? 'bg-slate-800 text-slate-200'
                            : 'bg-cyan-500/10 text-slate-200'
                        }`}
                      >
                        {msg.text}
                      </div>
                      <div className="text-xs text-slate-500">{msg.time}</div>
                    </div>
                  </div>
                ))}
                {sendingMessage && (
                  <div className="flex gap-3">
                    <div className="w-8 h-8 rounded-full flex-shrink-0 bg-gradient-to-br from-cyan-500 to-blue-600" />
                    <div className="px-4 py-2 bg-slate-800 rounded-lg text-sm text-slate-400">
                      Thinking...
                    </div>
                  </div>
                )}
              </div>

              {/* Suggested Prompts */}
              <div className="mb-4 flex flex-wrap gap-2">
                <button
                  onClick={() => setChatInput('Give me a quick executive summary of the latest findings.')}
                  className="px-3 py-1.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded-lg text-xs hover:bg-cyan-500/20 transition-all"
                >
                  Give me a quick executive summary
                </button>
              </div>

              {/* Input */}
              <div className="flex gap-2">
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleSendChat()}
                  placeholder="Ask for a summary, remediation plan, or attack path..."
                  className="flex-1 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={handleSendChat}
                  disabled={!chatInput.trim() || sendingMessage}
                  className="px-6 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg font-medium hover:from-cyan-400 hover:to-blue-500 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Send
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;