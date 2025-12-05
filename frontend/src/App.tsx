import {
  FormEvent,
  useEffect,
  useMemo,
  useState,
  type Dispatch,
  type ReactNode,
  type SetStateAction
} from 'react'

type ScanTool = 'Nmap' | 'Nuclei' | 'Nikto' | 'OpenVAS'
type ScanStatus = 'In Progress' | 'Completed' | 'Clean' | 'Failed'
type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
type FindingStatus = 'Open' | 'In Progress' | 'Resolved'
type TabKey = 'scans' | 'findings' | 'analytics' | 'assistant'
type ScanFilter = 'All' | 'Issues' | 'Clean' | 'Failed'

interface Scan {
  id: string
  target: string
  tools: ScanTool[]
  startedAt: string
  status: ScanStatus
  issues: number
  critical: number
  durationMinutes: number
  owner: string
  riskScore: number
  summary: string
  aiSummary: string
}

interface Finding {
  id: string
  host: string
  port?: number
  service?: string
  severity: Severity
  tool: ScanTool
  status: FindingStatus
  title: string
  description: string
  recommendation: string
}

interface ChatMessage {
  id: string
  sender: 'user' | 'ai'
  text: string
  time: string
}

interface FeatureCard {
  title: string
  description: string
  badge?: string
}

const mockScans: Scan[] = [
  {
    id: 'scan-1042',
    target: 'prod-api.internal',
    tools: ['Nmap', 'Nuclei'],
    startedAt: '2024-03-08T11:20:00Z',
    status: 'Completed',
    issues: 7,
    critical: 2,
    durationMinutes: 8,
    owner: 'Blue team',
    riskScore: 78,
    summary: 'OpenSSH 8.2p1, exposed admin panel, TLS1.0 enabled.',
    aiSummary: 'AI flagged 2 critical paths: outdated OpenSSH on port 22 and exposed admin dashboard on 8443. Recommend patch + restrict access lists.'
  },
  {
    id: 'scan-1041',
    target: 'payments.edge',
    tools: ['Nikto', 'OpenVAS'],
    startedAt: '2024-03-07T19:05:00Z',
    status: 'Completed',
    issues: 4,
    critical: 1,
    durationMinutes: 12,
    owner: 'Red team',
    riskScore: 71,
    summary: 'Directory listing enabled on /exports, outdated TLS ciphers.',
    aiSummary: 'One critical issue: directory listing exposes config backups. TLS allows 1.0/1.1. Prioritize hardening web server and ciphers.'
  },
  {
    id: 'scan-1036',
    target: 'staging.api',
    tools: ['Nmap', 'Nikto', 'Nuclei'],
    startedAt: '2024-03-05T08:40:00Z',
    status: 'Clean',
    issues: 0,
    critical: 0,
    durationMinutes: 6,
    owner: 'QA',
    riskScore: 12,
    summary: 'No exploitable issues found across probed services.',
    aiSummary: 'Environment looks clean. Only informational banners observed. Keep weekly cadence.'
  },
  {
    id: 'scan-1032',
    target: 'vpn-gateway',
    tools: ['OpenVAS'],
    startedAt: '2024-03-02T15:10:00Z',
    status: 'Failed',
    issues: 0,
    critical: 0,
    durationMinutes: 2,
    owner: 'Ops',
    riskScore: 0,
    summary: 'Scan interrupted by timeout.',
    aiSummary: 'Recon stopped after gateway throttled requests. Retry with reduced concurrency.'
  }
]

const mockFindings: Finding[] = [
  {
    id: 'finding-1',
    host: 'prod-api.internal',
    port: 22,
    service: 'OpenSSH 8.2p1',
    severity: 'Critical',
    tool: 'Nmap',
    status: 'Open',
    title: 'Outdated OpenSSH with known CVEs',
    description: 'Service banner indicates vulnerable OpenSSH build that allows privilege escalation paths.',
    recommendation: 'Upgrade to OpenSSH 9.x and rotate host keys.'
  },
  {
    id: 'finding-2',
    host: 'prod-api.internal',
    port: 8443,
    service: 'Custom admin panel',
    severity: 'High',
    tool: 'Nuclei',
    status: 'In Progress',
    title: 'Exposed admin console without MFA',
    description: 'Admin interface discovered with weak auth. MFA not enforced.',
    recommendation: 'Restrict to VPN, enable SSO + MFA, add WAF rule.'
  },
  {
    id: 'finding-3',
    host: 'payments.edge',
    port: 443,
    service: 'nginx',
    severity: 'Medium',
    tool: 'Nikto',
    status: 'Open',
    title: 'Deprecated TLS 1.0/1.1 accepted',
    description: 'TLS handshake allowed legacy protocols that downgrade security posture.',
    recommendation: 'Disable TLS 1.0/1.1, enforce modern ciphers.'
  },
  {
    id: 'finding-4',
    host: 'payments.edge',
    port: 80,
    service: 'http',
    severity: 'High',
    tool: 'OpenVAS',
    status: 'Open',
    title: 'Directory listing exposed',
    description: 'Listing enabled on /exports revealing config backups.',
    recommendation: 'Disable autoindex and move backups off public path.'
  },
  {
    id: 'finding-5',
    host: 'staging.api',
    port: 443,
    service: 'https',
    severity: 'Low',
    tool: 'Nmap',
    status: 'Resolved',
    title: 'Verbose banner information',
    description: 'Server exposes version headers that aid fingerprinting.',
    recommendation: 'Trim server headers; keep observability via logs instead.'
  },
  {
    id: 'finding-6',
    host: 'vpn-gateway',
    port: 443,
    service: 'vpn',
    severity: 'Info',
    tool: 'OpenVAS',
    status: 'Open',
    title: 'Scan blocked by rate limiting',
    description: 'Gateway throttled scan attempts; coverage incomplete.',
    recommendation: 'Allowlisted scanner IPs or schedule during low-traffic window.'
  }
]

const landingFeatures: FeatureCard[] = [
  {
    title: 'Multi-tool scans',
    description: 'Blend Nmap, Nuclei, Nikto, and OpenVAS findings into one pane.',
    badge: 'Recon'
  },
  {
    title: 'AI risk summaries',
    description: 'Get concise AI briefings per host with prioritized remediation.',
    badge: 'AI'
  },
  {
    title: 'Plugin-based design',
    description: 'Swap scanners or add new ones without touching the UI.',
    badge: 'Modular'
  }
]

const initialMessages: ChatMessage[] = [
  {
    id: 'msg-1',
    sender: 'ai',
    text: 'Hi! I can summarize scans, craft mitigations, or prep exec briefs. Pick a scan to start.',
    time: '2m ago'
  },
  {
    id: 'msg-2',
    sender: 'user',
    text: 'Give me a quick executive summary of the latest findings.',
    time: '2m ago'
  },
  {
    id: 'msg-3',
    sender: 'ai',
    text: 'Latest recon: 2 criticals on prod-api (OpenSSH + exposed admin). Payments edge has weak TLS and directory listing. Focus on hardening SSH and closing admin access.',
    time: 'moments ago'
  }
]

const filterOptions: { label: string; value: ScanFilter }[] = [
  { label: 'All', value: 'All' },
  { label: 'Issues', value: 'Issues' },
  { label: 'Clean', value: 'Clean' },
  { label: 'Failed', value: 'Failed' }
]

const statusStyles: Record<ScanStatus, string> = {
  'Completed': 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  'Clean': 'bg-sky-500/10 text-sky-200 border-sky-500/30',
  'In Progress': 'bg-amber-500/15 text-amber-100 border-amber-500/40',
  'Failed': 'bg-rose-500/15 text-rose-200 border-rose-500/35'
}

const severityStyles: Record<Severity, string> = {
  Critical: 'bg-gradient-to-r from-rose-500/20 via-red-500/10 to-orange-500/10 text-rose-100 border border-rose-500/40',
  High: 'bg-orange-500/15 text-orange-100 border border-orange-500/30',
  Medium: 'bg-amber-500/15 text-amber-100 border border-amber-500/30',
  Low: 'bg-emerald-500/12 text-emerald-100 border border-emerald-500/25',
  Info: 'bg-slate-500/10 text-slate-100 border border-slate-400/25'
}

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

const mockFetchScans = async (): Promise<Scan[]> => {
  await wait(350)
  return mockScans
}

const mockFetchFindings = async (): Promise<Finding[]> => {
  await wait(350)
  return mockFindings
}

const mockStartScan = async (tools: ScanTool[], target: string, id: string): Promise<Scan> => {
  await wait(1300)
  const issueCount = Math.floor(Math.random() * 5)
  const criticalCount = issueCount > 2 ? 1 : 0
  return {
    id,
    target,
    tools,
    startedAt: new Date().toISOString(),
    status: issueCount === 0 ? 'Clean' : 'Completed',
    issues: issueCount,
    critical: criticalCount,
    durationMinutes: Math.max(4, Math.round(Math.random() * 7 + 4)),
    owner: 'You',
    riskScore: issueCount === 0 ? 15 : Math.min(90, 48 + issueCount * 8),
    summary: issueCount === 0 ? 'No exploitable issues detected in latest sweep.' : 'Recon finished with notable exposures.',
    aiSummary:
      issueCount === 0
        ? 'Scan finished clean. Minor informational banners only.'
        : `AI spotted ${criticalCount} critical pattern${criticalCount === 1 ? '' : 's'} and ${issueCount} total issues. Prioritize patching and access control.`
  }
}

const mockSendChat = async (prompt: string): Promise<string> => {
  await wait(600)
  return `Synthesized response: I will correlate the latest scans and highlight top risks for "${prompt}". Immediate focus: tighten ingress controls and patch critical services.`
}

function App() {
  const [view, setView] = useState<'landing' | 'dashboard'>('landing')
  const [activeTab, setActiveTab] = useState<TabKey>('scans')
  const [selectedTools, setSelectedTools] = useState<ScanTool[]>(['Nmap', 'Nuclei'])
  const [target, setTarget] = useState('prod-edge.internal')
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [scanFilter, setScanFilter] = useState<ScanFilter>('All')
  const [scans, setScans] = useState<Scan[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>(initialMessages)
  const [chatInput, setChatInput] = useState('')
  const [sendingMessage, setSendingMessage] = useState(false)
  const [expandedHosts, setExpandedHosts] = useState<Record<string, boolean>>({})
  const [loadingData, setLoadingData] = useState(true)

  useEffect(() => {
    const load = async () => {
      setLoadingData(true)
      const [scanData, findingData] = await Promise.all([mockFetchScans(), mockFetchFindings()])
      setScans(scanData)
      setFindings(findingData)
      setSelectedScanId(scanData[0]?.id ?? null)
      setLoadingData(false)
    }
    load()
  }, [])

  useEffect(() => {
    if (!isScanning) return

    setScanProgress(12)
    const interval = setInterval(() => {
      setScanProgress((prev) => Math.min(96, prev + Math.random() * 14))
    }, 700)
    return () => clearInterval(interval)
  }, [isScanning])

  const uniqueToolsUsed = useMemo(
    () => new Set(scans.flatMap((scan) => scan.tools)).size,
    [scans]
  )

  const highCriticalCount = useMemo(
    () => findings.filter((f) => f.severity === 'High' || f.severity === 'Critical').length,
    [findings]
  )

  const overallRisk = useMemo(() => {
    if (!scans.length) return 0
    const total = scans.reduce((sum, scan) => sum + scan.riskScore, 0)
    return Math.round(total / scans.length)
  }, [scans])

  const groupedFindings = useMemo(() => {
    return findings.reduce<Record<string, Finding[]>>((acc, finding) => {
      if (!acc[finding.host]) acc[finding.host] = []
      acc[finding.host].push(finding)
      return acc
    }, {})
  }, [findings])

  const severityStats = useMemo(() => {
    return findings.reduce<Record<Severity, number>>(
      (acc, finding) => {
        acc[finding.severity] += 1
        return acc
      },
      { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
    )
  }, [findings])

  const toolStats = useMemo(() => {
    return findings.reduce<Record<ScanTool, number>>(
      (acc, finding) => {
        acc[finding.tool] += 1
        return acc
      },
      { Nmap: 0, Nuclei: 0, Nikto: 0, OpenVAS: 0 }
    )
  }, [findings])

  const filteredScans = useMemo(() => {
    return scans.filter((scan) => {
      if (scanFilter === 'Issues') return scan.issues > 0 || scan.critical > 0
      if (scanFilter === 'Clean') return scan.status === 'Clean'
      if (scanFilter === 'Failed') return scan.status === 'Failed'
      return true
    })
  }, [scans, scanFilter])

  const activeScan = useMemo(
    () => scans.find((scan) => scan.id === selectedScanId) ?? scans[0],
    [scans, selectedScanId]
  )

  const toggleTool = (tool: ScanTool) => {
    setSelectedTools((prev) =>
      prev.includes(tool) ? prev.filter((t) => t !== tool) : [...prev, tool]
    )
  }

  const handleStartScan = async () => {
    if (!target.trim()) return
    const toolsToUse = selectedTools.length ? selectedTools : ['Nmap']
    const id = `scan-${Date.now()}`
    const draft: Scan = {
      id,
      target,
      tools: toolsToUse,
      startedAt: new Date().toISOString(),
      status: 'In Progress',
      issues: 0,
      critical: 0,
      durationMinutes: 0,
      owner: 'You',
      riskScore: 10,
      summary: 'Recon kicked off…',
      aiSummary: 'Scan running. I will summarize once results stream in.'
    }

    setIsScanning(true)
    setScans((prev) => [draft, ...prev])
    setSelectedScanId(id)

    try {
      const completed = await mockStartScan(toolsToUse, target, id)
      setScans((prev) => prev.map((scan) => (scan.id === id ? completed : scan)))

      const generatedFinding: Finding = {
        id: `finding-${Date.now()}`,
        host: target,
        port: 443,
        service: `${toolsToUse[0]} target`,
        severity: completed.issues > 0 ? 'Medium' : 'Info',
        tool: toolsToUse[0],
        status: completed.issues > 0 ? 'Open' : 'Resolved',
        title: completed.issues > 0 ? 'New surface detected' : 'Scan completed cleanly',
        description:
          completed.issues > 0
            ? 'Recon discovered a new surface area that should be triaged.'
            : 'Nothing risky detected on this target in the latest run.',
        recommendation:
          completed.issues > 0 ? 'Review new service, lock down ingress, and validate patching.' : 'Keep monitoring cadence weekly.'
      }

      setFindings((prev) => [generatedFinding, ...prev])
    } finally {
      setIsScanning(false)
      setScanProgress(100)
      setTimeout(() => setScanProgress(0), 900)
    }
  }

  const handleCancelScan = () => {
    setIsScanning(false)
    setScanProgress(0)
    setScans((prev) =>
      prev.map((scan) =>
        scan.status === 'In Progress'
          ? {
              ...scan,
              status: 'Failed',
              summary: 'Scan cancelled before completion.',
              aiSummary: 'Scan aborted by operator. No results collected.'
            }
          : scan
      )
    )
  }

  const handleSendMessage = async (event: FormEvent) => {
    event.preventDefault()
    if (!chatInput.trim()) return
    const userMessage: ChatMessage = {
      id: `msg-${Date.now()}`,
      sender: 'user',
      text: chatInput,
      time: 'just now'
    }
    setMessages((prev) => [...prev, userMessage])
    setChatInput('')
    setSendingMessage(true)
    const aiReply = await mockSendChat(userMessage.text)
    setMessages((prev) => [
      ...prev,
      {
        id: `msg-${Date.now()}-ai`,
        sender: 'ai',
        text: aiReply,
        time: 'moments later'
      }
    ])
    setSendingMessage(false)
  }

  return (
    <div className="min-h-screen text-slate-50 bg-gradient-to-br from-[#0b1025] via-[#0b0f1d] to-[#050915] relative overflow-hidden">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-10 -top-10 h-72 w-72 bg-purple-600/25 blur-[90px]" />
        <div className="absolute right-0 top-10 h-64 w-64 bg-cyan-400/20 blur-[90px]" />
        <div className="absolute bottom-0 left-10 h-60 w-60 bg-blue-500/20 blur-[90px]" />
      </div>

      <div className="relative mx-auto max-w-6xl px-6 pb-16">
        <header className="flex items-center justify-between py-6">
          <div className="flex items-center gap-3">
            <div className="rounded-2xl bg-gradient-to-br from-blue-600 to-cyan-400 p-2 shadow-lg shadow-blue-900/30">
              <span className="text-xl">🛰️</span>
            </div>
            <div>
              <p className="text-xs uppercase tracking-[0.28em] text-slate-300">Recon Copilot</p>
              <h1 className="text-xl font-semibold text-white">AI recon & vulnerability dashboard</h1>
            </div>
          </div>
          <div className="flex items-center gap-3 rounded-full border border-white/10 bg-white/5 px-4 py-2 backdrop-blur-lg">
            <div className="text-right">
              <p className="text-xs text-slate-300">Logged in as</p>
              <p className="text-sm font-semibold text-white">Ava Ops</p>
            </div>
            <div className="h-10 w-10 rounded-full bg-gradient-to-br from-blue-700 to-sky-500" />
          </div>
        </header>

        {view === 'landing' ? (
          <Landing onEnter={() => setView('dashboard')} />
        ) : (
          <>
            <div className="mb-4 flex">
              <BackButton
                label="← Back to default"
                onBack={() => {
                  setView('landing')
                  setActiveTab('scans')
                }}
              />
            </div>
            <Dashboard
              activeTab={activeTab}
              setActiveTab={setActiveTab}
              metrics={{
                totalScans: scans.length,
                highCritical: highCriticalCount,
                toolsUsed: uniqueToolsUsed,
                overallRisk
              }}
              onBackToDefault={() => {
                setView('dashboard')
                setActiveTab('scans')
              }}
              target={target}
              setTarget={setTarget}
              selectedTools={selectedTools}
              toggleTool={toggleTool}
              isScanning={isScanning}
              scanProgress={scanProgress}
              onStartScan={handleStartScan}
              onCancelScan={handleCancelScan}
              scans={filteredScans}
              allScans={scans}
              scanFilter={scanFilter}
              setScanFilter={setScanFilter}
              findings={findings}
              groupedFindings={groupedFindings}
              severityStats={severityStats}
              toolStats={toolStats}
              expandedHosts={expandedHosts}
              setExpandedHosts={setExpandedHosts}
              selectedScanId={selectedScanId}
              setSelectedScanId={setSelectedScanId}
              activeScan={activeScan}
              messages={messages}
              chatInput={chatInput}
              setChatInput={setChatInput}
              onSendMessage={handleSendMessage}
              sendingMessage={sendingMessage}
              loadingData={loadingData}
            />
          </>
        )}
      </div>
    </div>
  )
}

interface DashboardProps {
  activeTab: TabKey
  setActiveTab: Dispatch<SetStateAction<TabKey>>
  metrics: { totalScans: number; highCritical: number; toolsUsed: number; overallRisk: number }
  onBackToDefault: () => void
  target: string
  setTarget: Dispatch<SetStateAction<string>>
  selectedTools: ScanTool[]
  toggleTool: (tool: ScanTool) => void
  isScanning: boolean
  scanProgress: number
  onStartScan: () => void
  onCancelScan: () => void
  scans: Scan[]
  allScans: Scan[]
  scanFilter: ScanFilter
  setScanFilter: Dispatch<SetStateAction<ScanFilter>>
  findings: Finding[]
  groupedFindings: Record<string, Finding[]>
  severityStats: Record<Severity, number>
  toolStats: Record<ScanTool, number>
  expandedHosts: Record<string, boolean>
  setExpandedHosts: Dispatch<SetStateAction<Record<string, boolean>>>
  selectedScanId: string | null
  setSelectedScanId: Dispatch<SetStateAction<string | null>>
  activeScan?: Scan
  messages: ChatMessage[]
  chatInput: string
  setChatInput: Dispatch<SetStateAction<string>>
  onSendMessage: (event: FormEvent) => Promise<void>
  sendingMessage: boolean
  loadingData: boolean
}

function Dashboard({
  activeTab,
  setActiveTab,
  metrics,
  onBackToDefault,
  target,
  setTarget,
  selectedTools,
  toggleTool,
  isScanning,
  scanProgress,
  onStartScan,
  onCancelScan,
  scans,
  allScans,
  scanFilter,
  setScanFilter,
  findings,
  groupedFindings,
  severityStats,
  toolStats,
  expandedHosts,
  setExpandedHosts,
  selectedScanId,
  setSelectedScanId,
  activeScan,
  messages,
  chatInput,
  setChatInput,
  onSendMessage,
  sendingMessage,
  loadingData
}: DashboardProps) {
  return (
    <div className="space-y-8">
      {activeTab !== 'scans' && (
        <div className="flex">
          <BackButton onBack={() => {
            onBackToDefault()
          }} />
        </div>
      )}
      <Card className="border-white/10 bg-white/5">
        <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/10 px-3 py-1 text-xs text-slate-200">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              Live preview
            </div>
            <h2 className="mt-3 text-3xl font-semibold text-white">Recon Copilot dashboard</h2>
            <p className="mt-2 text-slate-300">
              Wire up Nmap, Nuclei, Nikto, and OpenVAS feeds—AI will summarize everything for you.
            </p>
          </div>
          <button
            className="rounded-full bg-blue-500 px-5 py-2.5 text-sm font-medium text-white shadow-md transition hover:bg-blue-600 active:bg-blue-700"
            onClick={() => setActiveTab('assistant')}
          >
            Open AI assistant
          </button>
        </div>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Total Scans" value={metrics.totalScans} helper="Last 30 days" accent="from-blue-600 to-sky-500" />
        <MetricCard
          label="High/Critical Issues"
          value={metrics.highCritical}
          helper="Across all hosts"
          accent="from-rose-500 to-orange-400"
        />
        <MetricCard label="Tools Used" value={metrics.toolsUsed} helper="Nmap, Nuclei, Nikto, OpenVAS" accent="from-cyan-400 to-blue-400" />
        <MetricCard label="Overall Risk Score" value={`${metrics.overallRisk}%`} helper="Weighted by severity" accent="from-amber-400 to-blue-600" />
      </div>

      <Tabs activeTab={activeTab} onChange={setActiveTab} />

      <Card>
        {activeTab === 'scans' && (
          <ScansTab
            target={target}
            setTarget={setTarget}
            selectedTools={selectedTools}
            toggleTool={toggleTool}
            isScanning={isScanning}
            scanProgress={scanProgress}
            onStartScan={onStartScan}
            onCancelScan={onCancelScan}
            scans={scans}
            scanFilter={scanFilter}
            setScanFilter={setScanFilter}
            loadingData={loadingData}
          />
        )}
        {activeTab === 'findings' && (
          <FindingsTab
            groupedFindings={groupedFindings}
            expandedHosts={expandedHosts}
            setExpandedHosts={setExpandedHosts}
            loadingData={loadingData}
          />
        )}
        {activeTab === 'analytics' && (
          <AnalyticsTab severityStats={severityStats} toolStats={toolStats} loadingData={loadingData} />
        )}
        {activeTab === 'assistant' && (
          <AssistantTab
            activeScan={activeScan}
            scans={allScans}
            selectedScanId={selectedScanId}
            setSelectedScanId={setSelectedScanId}
            messages={messages}
            chatInput={chatInput}
            setChatInput={setChatInput}
            onSendMessage={onSendMessage}
            sendingMessage={sendingMessage}
          />
        )}
      </Card>
    </div>
  )
}

function Landing({ onEnter }: { onEnter: () => void }) {
  return (
    <div className="space-y-10">
      <Card className="border-white/10 bg-white/5">
        <div className="grid gap-10 md:grid-cols-2 md:items-center">
          <div className="space-y-4">
            <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/10 px-3 py-1 text-xs text-slate-200">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              New
            </div>
            <h2 className="text-4xl font-semibold text-white">Recon Copilot</h2>
            <p className="text-lg text-slate-200">
              AI-powered recon & vulnerability dashboard. Merge Nmap, Nuclei, Nikto, and OpenVAS into one clear storyline.
            </p>
            <div className="flex gap-3">
              <button
                className="rounded-full bg-blue-500 px-5 py-2.5 text-sm font-medium text-white shadow-md transition hover:bg-blue-600 active:bg-blue-700"
                onClick={onEnter}
              >
                Go to Dashboard
              </button>
            </div>
          </div>
          <div className="rounded-3xl border border-white/10 bg-gradient-to-br from-blue-700/25 via-sky-600/15 to-cyan-400/12 p-1">
            <div className="rounded-2xl bg-black/60 p-6 shadow-glass">
              <div className="flex items-center gap-3 text-sm text-slate-200">
                <span className="h-2 w-2 rounded-full bg-emerald-400" />
                Unified recon feed ready. AI summarization on standby.
              </div>
              <div className="mt-6 grid gap-4 md:grid-cols-2">
                <LandingStat label="Targets watched" value="28" />
                <LandingStat label="Criticals" value="6" />
                <LandingStat label="Avg. SLA" value="14h" />
                <LandingStat label="Tools" value="4" />
              </div>
            </div>
          </div>
        </div>
      </Card>

      <div className="grid gap-4 md:grid-cols-3">
        {landingFeatures.map((feature) => (
          <Card key={feature.title} className="border-white/10 bg-white/5 hover:-translate-y-1 hover:border-white/20 transition">
            <div className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-slate-300">
              <span className="h-2 w-2 rounded-full bg-cyan-400" />
              {feature.badge}
            </div>
            <h3 className="mt-3 text-lg font-semibold text-white">{feature.title}</h3>
            <p className="mt-2 text-sm text-slate-300">{feature.description}</p>
          </Card>
        ))}
      </div>
    </div>
  )
}

function Tabs({ activeTab, onChange }: { activeTab: TabKey; onChange: (tab: TabKey) => void }) {
  const tabs: { key: TabKey; label: string }[] = [
    { key: 'scans', label: 'Scans' },
    { key: 'findings', label: 'Security Findings' },
    { key: 'analytics', label: 'Analytics' },
    { key: 'assistant', label: 'AI Assistant' }
  ]

  return (
    <div className="flex flex-wrap gap-3">
      {tabs.map((tab) => (
        <button
          key={tab.key}
          className={`rounded-full border px-4 py-2 text-sm font-semibold transition ${
            activeTab === tab.key
              ? 'border-white/70 bg-white/15 text-white shadow-lg shadow-blue-900/30'
              : 'border-white/10 bg-white/5 text-slate-200 hover:border-white/30'
          }`}
          onClick={() => onChange(tab.key)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  )
}

function ScansTab({
  target,
  setTarget,
  selectedTools,
  toggleTool,
  isScanning,
  scanProgress,
  onStartScan,
  onCancelScan,
  scans,
  scanFilter,
  setScanFilter,
  loadingData
}: {
  target: string
  setTarget: Dispatch<SetStateAction<string>>
  selectedTools: ScanTool[]
  toggleTool: (tool: ScanTool) => void
  isScanning: boolean
  scanProgress: number
  onStartScan: () => void
  onCancelScan: () => void
  scans: Scan[]
  scanFilter: ScanFilter
  setScanFilter: Dispatch<SetStateAction<ScanFilter>>
  loadingData: boolean
}) {
  return (
    <div className="space-y-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-2">
            <h3 className="text-xl font-semibold text-white">Scans</h3>
            <p className="text-sm text-slate-300">Kick off a new scan or review the latest runs.</p>
          </div>
          <div className="flex flex-col gap-3 rounded-2xl border border-white/10 bg-white/5 p-3 sm:flex-row sm:items-center">
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Target (e.g., api.internal)"
              className="w-full rounded-xl border border-white/10 bg-black/30 px-3 py-2 text-sm text-white outline-none placeholder:text-slate-400 focus:border-white/40"
            />
            <button
              onClick={onStartScan}
              className="w-full rounded-full bg-blue-500 px-5 py-2.5 text-sm font-medium text-white shadow-md transition hover:bg-blue-600 active:bg-blue-700 sm:w-auto"
            >
              New Scan
            </button>
          </div>
        </div>

      <div className="flex flex-wrap items-center gap-2">
        {(['Nmap', 'Nuclei', 'Nikto', 'OpenVAS'] as ScanTool[]).map((tool) => {
          const selected = selectedTools.includes(tool)
          return (
            <button
              key={tool}
              onClick={() => toggleTool(tool)}
              className={`rounded-full border px-3 py-2 text-xs font-semibold transition ${
                selected
                  ? 'border-white/60 bg-white/20 text-white shadow-lg shadow-blue-900/30'
                  : 'border-white/10 bg-white/5 text-slate-200 hover:border-white/30'
              }`}
            >
              {tool}
            </button>
          )
        })}
      </div>

      {isScanning && (
        <div className="rounded-2xl border border-white/10 bg-white/10 p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-semibold text-white">Scanning…</p>
              <p className="text-xs text-slate-300">AI will summarize results once finished.</p>
            </div>
            <div className="flex items-center gap-3">
              <div className="h-2 w-40 overflow-hidden rounded-full bg-white/10">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-blue-400 to-cyan-300 transition-all"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
              <button
                onClick={onCancelScan}
                className="rounded-full border border-white/20 px-3 py-1 text-xs text-white hover:border-rose-300 hover:text-rose-100"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {filterOptions.map((option) => (
          <button
            key={option.value}
            className={`rounded-full border px-3 py-1 text-xs font-semibold transition ${
              scanFilter === option.value
                ? 'border-white/70 bg-white/15 text-white'
                : 'border-white/10 bg-white/5 text-slate-200 hover:border-white/30'
            }`}
            onClick={() => setScanFilter(option.value)}
          >
            {option.label}
          </button>
        ))}
      </div>

      <div className="overflow-hidden rounded-2xl border border-white/10 bg-black/30">
        <div className="grid grid-cols-12 gap-4 border-b border-white/5 px-4 py-3 text-xs font-semibold uppercase tracking-wide text-slate-300">
          <span className="col-span-3">Target</span>
          <span className="col-span-3">Tools</span>
          <span className="col-span-2">Issues</span>
          <span className="col-span-2">Status</span>
          <span className="col-span-2 text-right">Risk</span>
        </div>
        <div className="divide-y divide-white/5">
          {loadingData &&
            Array.from({ length: 3 }).map((_, idx) => (
              <div key={idx} className="grid grid-cols-12 gap-4 px-4 py-4 text-sm text-slate-300">
                <Skeleton className="col-span-3 h-4" />
                <Skeleton className="col-span-3 h-4" />
                <Skeleton className="col-span-2 h-4" />
                <Skeleton className="col-span-2 h-4" />
                <Skeleton className="col-span-2 h-4" />
              </div>
            ))}
          {!loadingData &&
            scans.map((scan) => (
              <div
                key={scan.id}
                className="grid grid-cols-12 gap-4 px-4 py-4 text-sm text-slate-200 hover:bg-white/5"
              >
                <div className="col-span-3">
                  <p className="font-semibold text-white">{scan.target}</p>
                  <p className="text-xs text-slate-400">{new Date(scan.startedAt).toLocaleString()}</p>
                </div>
                <div className="col-span-3 flex flex-wrap gap-2">
                  {scan.tools.map((tool) => (
                    <span
                      key={tool}
                      className="rounded-full border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-200"
                    >
                      {tool}
                    </span>
                  ))}
                </div>
                <div className="col-span-2">
                  <p className="font-semibold text-white">{scan.issues} issues</p>
                  <p className="text-xs text-rose-200">{scan.critical} critical</p>
                </div>
                <div className="col-span-2">
                  <span className={`rounded-full px-2 py-1 text-xs font-semibold ${statusStyles[scan.status]}`}>
                    {scan.status}
                  </span>
                </div>
                <div className="col-span-2 text-right">
                  <p className="text-lg font-semibold text-white">{scan.riskScore}%</p>
                  <p className="text-xs text-slate-400">{scan.summary}</p>
                </div>
              </div>
            ))}
        </div>
      </div>
    </div>
  )
}

function FindingsTab({
  groupedFindings,
  expandedHosts,
  setExpandedHosts,
  loadingData
}: {
  groupedFindings: Record<string, Finding[]>
  expandedHosts: Record<string, boolean>
  setExpandedHosts: Dispatch<SetStateAction<Record<string, boolean>>>
  loadingData: boolean
}) {
  const toggleHost = (host: string) => {
    setExpandedHosts({ ...expandedHosts, [host]: !expandedHosts[host] })
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-semibold text-white">Security Findings</h3>
          <p className="text-sm text-slate-300">Grouped by host with severity and status.</p>
        </div>
      </div>

      <div className="space-y-3">
        {loadingData &&
          Array.from({ length: 2 }).map((_, idx) => (
            <Card key={idx} className="border-white/10 bg-white/5">
              <Skeleton className="h-5 w-52" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-2/3" />
            </Card>
          ))}

        {!loadingData &&
          Object.entries(groupedFindings).map(([host, items]) => {
            const severities = items.reduce<Record<Severity, number>>(
              (acc, finding) => {
                acc[finding.severity] += 1
                return acc
              },
              { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
            )

            return (
              <div
                key={host}
                className="flex flex-col gap-3 rounded-2xl border border-slate-800/70 bg-slate-900/70 px-5 py-4 transition-colors hover:bg-slate-900/90"
              >
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <div>
                    <h4 className="text-lg font-medium text-slate-50">{host}</h4>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <span className="rounded-full border border-slate-800 bg-black/30 px-2 py-1">{items.length} issues</span>
                      {Object.entries(severities)
                        .filter(([, count]) => count > 0)
                        .map(([severity, count]) => (
                          <span
                            key={severity}
                            className={`rounded-full px-2 py-1 text-[11px] font-semibold ${severityStyles[severity as Severity]}`}
                          >
                            {severity} • {count}
                          </span>
                        ))}
                    </div>
                  </div>
                  <button
                    onClick={() => toggleHost(host)}
                    className="rounded-full border border-slate-600/70 px-3 py-1.5 text-sm font-semibold text-slate-100 transition hover:border-slate-300/80"
                  >
                    {expandedHosts[host] ? 'Hide details' : 'View details'}
                  </button>
                </div>

                {expandedHosts[host] && (
                  <div className="space-y-3">
                    {items.map((finding) => (
                      <div
                        key={finding.id}
                        className="rounded-xl border border-slate-800/70 bg-black/30 p-3"
                      >
                        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`rounded-full px-2 py-1 text-[11px] font-semibold ${severityStyles[finding.severity]}`}>
                              {finding.severity}
                            </span>
                            <span className="rounded-full border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-200">
                              {finding.tool}
                            </span>
                            {finding.port && (
                              <span className="rounded-full border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-200">
                                {finding.service} • {finding.port}
                              </span>
                            )}
                            <span className="rounded-full border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-200">
                              {finding.status}
                            </span>
                          </div>
                          <div className="text-right text-xs text-slate-400">#{finding.id}</div>
                        </div>
                        <h5 className="mt-2 text-base font-semibold text-white">{finding.title}</h5>
                        <p className="text-sm text-slate-200">{finding.description}</p>
                        <p className="text-xs text-emerald-200">Remediation: {finding.recommendation}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
      </div>
    </div>
  )
}

function AnalyticsTab({
  severityStats,
  toolStats,
  loadingData
}: {
  severityStats: Record<Severity, number>
  toolStats: Record<ScanTool, number>
  loadingData: boolean
}) {
  const maxSeverity = Math.max(...Object.values(severityStats))
  const maxTool = Math.max(...Object.values(toolStats))

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-xl font-semibold text-white">Analytics</h3>
        <p className="text-sm text-slate-300">Issue breakdown by severity and scanner.</p>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div className="rounded-3xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-lg backdrop-blur-md">
          <h4 className="text-sm font-semibold uppercase tracking-wide text-slate-200/80">Issues by severity</h4>
          <div className="mt-4 space-y-3">
            {loadingData &&
              Array.from({ length: 5 }).map((_, idx) => <Skeleton key={idx} className="h-8 w-full" />)}
            {!loadingData &&
              (Object.entries(severityStats) as [Severity, number][]).map(([severity, count]) => (
                <div key={severity} className="flex items-center gap-3 text-sm text-slate-100/90">
                  <span className={`min-w-[88px] rounded-full px-3 py-1 text-center text-xs font-semibold ${severityStyles[severity]}`}>
                    {severity}
                  </span>
                  <div className="h-2 flex-1 rounded-full bg-slate-800/70">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-blue-400 to-cyan-300"
                      style={{ width: `${maxSeverity ? (count / maxSeverity) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="w-10 text-right text-slate-200">{count}</span>
                </div>
              ))}
          </div>
        </div>

        <div className="rounded-3xl border border-slate-700/60 bg-slate-900/70 p-5 shadow-lg backdrop-blur-md">
          <h4 className="text-sm font-semibold uppercase tracking-wide text-slate-200/80">Issues by tool</h4>
          <div className="mt-4 space-y-3">
            {loadingData &&
              Array.from({ length: 4 }).map((_, idx) => <Skeleton key={idx} className="h-8 w-full" />)}
            {!loadingData &&
              (Object.entries(toolStats) as [ScanTool, number][]).map(([tool, count]) => (
                <div key={tool} className="flex items-center gap-3 text-sm text-slate-100/90">
                  <span className="min-w-[88px] rounded-full border border-slate-700/70 bg-slate-800/60 px-3 py-1 text-center text-xs font-semibold text-slate-200">
                    {tool}
                  </span>
                  <div className="h-2 flex-1 rounded-full bg-slate-800/70">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-blue-400 to-sky-400"
                      style={{ width: `${maxTool ? (count / maxTool) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="w-10 text-right text-slate-200">{count}</span>
                </div>
              ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function AssistantTab({
  activeScan,
  scans,
  selectedScanId,
  setSelectedScanId,
  messages,
  chatInput,
  setChatInput,
  onSendMessage,
  sendingMessage
}: {
  activeScan?: Scan
  scans: Scan[]
  selectedScanId: string | null
  setSelectedScanId: Dispatch<SetStateAction<string | null>>
  messages: ChatMessage[]
  chatInput: string
  setChatInput: Dispatch<SetStateAction<string>>
  onSendMessage: (event: FormEvent) => Promise<void>
  sendingMessage: boolean
}) {
  return (
    <div className="grid gap-6 lg:grid-cols-5">
      <div className="space-y-4 rounded-2xl border border-white/10 bg-black/30 p-4 lg:col-span-2">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-lg font-semibold text-white">Selected scan</h4>
            <p className="text-xs text-slate-300">AI summary for the latest run.</p>
          </div>
          <span className="rounded-full border border-emerald-400/40 bg-emerald-400/10 px-3 py-1 text-xs font-semibold text-emerald-100">
            AI Summary
          </span>
        </div>

        <select
          value={selectedScanId ?? ''}
          onChange={(e) => setSelectedScanId(e.target.value)}
          className="w-full rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-white outline-none focus:border-white/40"
        >
          {!scans.length && <option value="">No scans yet</option>}
          {scans.map((scan) => (
            <option key={scan.id} value={scan.id}>
              {scan.target} • {scan.tools.join(', ')}
            </option>
          ))}
        </select>

        <div className="rounded-xl border border-white/5 bg-white/5 p-4">
          <p className="text-xs uppercase tracking-wide text-slate-300">Summary</p>
          <p className="mt-2 text-sm text-slate-50">{activeScan?.aiSummary}</p>
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs text-slate-200">
          <div className="rounded-xl border border-white/10 bg-black/20 p-3">
            <p className="text-slate-400">Issues</p>
            <p className="text-xl font-semibold text-white">{activeScan?.issues ?? 0}</p>
          </div>
          <div className="rounded-xl border border-white/10 bg-black/20 p-3">
            <p className="text-slate-400">Risk</p>
            <p className="text-xl font-semibold text-white">{activeScan?.riskScore ?? 0}%</p>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-white/10 bg-white/5 p-4 lg:col-span-3">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-lg font-semibold text-white">AI Assistant</h4>
            <p className="text-xs text-slate-300">Ask the AI to summarize or suggest mitigations.</p>
          </div>
          <span className="h-2 w-2 rounded-full bg-emerald-400" />
        </div>

        <div className="mt-4 flex flex-col gap-3">
          <div className="h-80 overflow-y-auto rounded-xl border border-white/5 bg-black/30 p-3">
            <div className="space-y-3">
              {messages.map((message) => (
                <div
                  key={message.id}
                  className={`flex ${message.sender === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  <div
                    className={`max-w-[70%] rounded-2xl px-4 py-3 text-sm ${
                      message.sender === 'user'
                        ? 'bg-gradient-to-r from-blue-600 to-cyan-400 text-white'
                        : 'bg-white/10 text-slate-100'
                    }`}
                  >
                    <p>{message.text}</p>
                    <p className="mt-1 text-[11px] text-slate-200/80">{message.time}</p>
                  </div>
                </div>
              ))}
              {sendingMessage && (
                <div className="flex justify-start">
                  <div className="max-w-[70%] rounded-2xl bg-white/10 px-4 py-3 text-sm text-slate-100">
                    <div className="flex items-center gap-2">
                      <span className="h-2 w-2 animate-pulse rounded-full bg-white/60" />
                      <span className="h-2 w-2 animate-pulse rounded-full bg-white/60" />
                      <span className="h-2 w-2 animate-pulse rounded-full bg-white/60" />
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          <form onSubmit={onSendMessage} className="flex flex-col gap-2 sm:flex-row">
            <textarea
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              placeholder="Ask for a summary, remediation plan, or attack path…"
              className="h-24 flex-1 rounded-xl border border-white/10 bg-black/30 px-3 py-2 text-sm text-white outline-none placeholder:text-slate-400 focus:border-white/40"
            />
            <button
              type="submit"
              className="min-w-[120px] self-end rounded-full bg-blue-500 px-5 py-2.5 text-sm font-medium text-white shadow-md transition hover:bg-blue-600 active:bg-blue-700"
            >
              Send
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}

function LandingStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/5 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-300">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-white">{value}</p>
    </div>
  )
}

function BackButton({ onBack, label = '← Back to dashboard' }: { onBack: () => void; label?: string }) {
  return (
    <button
      className="inline-flex items-center gap-2 rounded-full border border-slate-600/70 bg-black/30 px-3 py-1.5 text-sm text-slate-300 transition hover:border-slate-400 hover:text-white"
      onClick={onBack}
    >
      {label}
    </button>
  )
}

function Card({
  children,
  className = ''
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <div className={`rounded-3xl border border-white/5 bg-white/10 p-5 shadow-glass backdrop-blur-xl ${className}`}>
      {children}
    </div>
  )
}

function MetricCard({
  label,
  value,
  helper,
  accent
}: {
  label: string
  value: number | string
  helper?: string
  accent: string
}) {
  return (
    <Card className="border-white/10 bg-white/5">
      <div className="flex items-center gap-3">
        <div className={`h-10 w-10 rounded-2xl bg-gradient-to-br ${accent} opacity-90`} />
        <div>
          <p className="text-xs uppercase tracking-wide text-slate-300">{label}</p>
          <p className="text-2xl font-semibold text-white">{value}</p>
          {helper && <p className="text-xs text-slate-400">{helper}</p>}
        </div>
      </div>
    </Card>
  )
}

function Skeleton({ className }: { className?: string }) {
  return <div className={`animate-pulse rounded-lg bg-white/10 ${className}`} />
}

export default App
