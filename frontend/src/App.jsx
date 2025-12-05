import { useState } from 'react'
import ReactMarkdown from 'react-markdown'
import './App.css'

function App() {
  const [target, setTarget] = useState('localhost')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [error, setError] = useState(null)

  const runScan = async () => {
    setLoading(true)
    setError(null)
    setResults(null)
    
    try {
      console.log('Starting scan...')
      const response = await fetch('http://localhost:8000/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target })
      })
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      
      const data = await response.json()
      console.log('Scan complete:', data)
      setResults(data)
    } catch (error) {
      console.error('Scan failed:', error)
      setError(error.message)
    } finally {
      setLoading(false)
    }
  }

  const applyFix = async (vulnName, vulnSeverity) => {
    try {
      console.log(`Applying fix for: ${vulnName}`)
      
      // Map vulnerability to fix parameters
      let fixParams = {}
      const vulnLower = vulnName.toLowerCase()
      
      if (vulnLower.includes('password') || vulnLower.includes('weak') || vulnLower.includes('credential')) {
        fixParams = {
          fix_type: 'update_password',
          container: 'analist-db-1'
        }
      } else if (vulnLower.includes('port') || vulnLower.includes('exposed')) {
        fixParams = {
          fix_type: 'close_port',
          port: '33060',
          container: 'analist-db-1'
        }
      } else if (vulnLower.includes('outdated') || vulnLower.includes('version') || vulnLower.includes('old')) {
        fixParams = {
          fix_type: 'update_software',
          container: 'analist-wordpress-1'
        }
      } else if (vulnLower.includes('user') || vulnLower.includes('admin') || vulnLower.includes('privilege')) {
        fixParams = {
          fix_type: 'disable_user',
          username: 'admin'
        }
      } else {
        // Generic fix
        fixParams = {
          fix_type: 'generic',
          vulnerability: vulnName
        }
      }
      
      const response = await fetch('http://localhost:8000/fix', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(fixParams)
      })
      
      const data = await response.json()
      
      if (data.success) {
        alert('✅ Fix Applied!\n\n' + data.fixes_applied.join('\n'))
        // Optional: Re-run scan after fix
        // await runScan()
      } else {
        alert('❌ Fix Failed: ' + (data.error || 'Unknown error'))
      }
    } catch (error) {
      console.error('Fix failed:', error)
      alert('Failed to apply fix: ' + error.message)
    }
  }

  const getSeverityColor = (severity) => {
    const sev = severity?.toLowerCase() || ''
    if (sev.includes('critical')) return '#dc2626'
    if (sev.includes('high')) return '#ea580c'
    if (sev.includes('medium')) return '#ca8a04'
    return '#71717a'
  }

  return (
    <div className="App">
      <header>
        <div className="logo">
          <span className="shield">🛡️</span>
          <h1>CyberSec AI Agent</h1>
        </div>
        <p className="tagline">AI-Powered Security Analysis for SMBs</p>
      </header>
      
      <div className="scan-section">
        <div className="scan-input">
          <input 
            type="text" 
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Enter target to scan (e.g., localhost)"
            disabled={loading}
          />
          <button onClick={runScan} disabled={loading} className="scan-button">
            {loading ? (
              <>
                <span className="spinner"></span>
                Scanning Network...
              </>
            ) : (
              'Run Security Scan'
            )}
          </button>
        </div>
        
        {loading && (
          <div className="loading-info">
            <p>🔍 Scanning network infrastructure...</p>
            <p>⏱️ This may take 30-60 seconds</p>
          </div>
        )}
      </div>

      {error && (
        <div className="error-box">
          <h3>❌ Error</h3>
          <p>{error}</p>
          <p>Make sure the backend is running on http://localhost:8000</p>
        </div>
      )}

      {results && (
        <div className="results-container">
          {/* Main Analysis */}
          <div className="main-analysis">
            <div className="section ai-section">
              <h2>🤖 AI Security Analysis</h2>
              <div className="analysis-content">
                {results.ai_analysis ? (
                  <div className="markdown-content">
                    <ReactMarkdown>
                      {results.ai_analysis}
                    </ReactMarkdown>
                  </div>
                ) : (
                  <p className="placeholder">No analysis available</p>
                )}
              </div>
              {results.targets_scanned && (
                <p className="scan-meta">✅ Scanned {results.targets_scanned} network targets</p>
              )}
            </div>
            
            <details className="raw-section">
              <summary>📋 View Raw Scanner Output</summary>
              <div className="raw-content">
                {results.raw_output ? (
                  <pre className="raw-output">{results.raw_output}</pre>
                ) : (
                  <p className="placeholder">No raw output available</p>
                )}
              </div>
            </details>
          </div>

          {/* Sidebar with Quick Summary */}
          <div className="vulnerabilities-sidebar">
            <h3>🚨 Quick Summary</h3>
            
            {results.vulnerabilities_summary && results.vulnerabilities_summary.length > 0 ? (
              <>
                <div className="vuln-list">
                  {results.vulnerabilities_summary.map((vuln, idx) => (
                    <div key={idx} className="vuln-card">
                      <div 
                        className="vuln-severity-badge"
                        style={{ 
                          backgroundColor: getSeverityColor(vuln.severity),
                          color: 'white'
                        }}
                      >
                        {vuln.severity}
                      </div>
                      <div className="vuln-name">{vuln.name}</div>
                      {vuln.fix && (
                        <div className="vuln-fix">
                          <strong>Quick Fix:</strong> {vuln.fix}
                        </div>
                      )}
                      
                      {/* Auto-Fix Button */}
                      <button 
                        className="fix-button"
                        onClick={() => applyFix(vuln.name, vuln.severity)}
                      >
                        🔧 Apply Fix
                      </button>
                    </div>
                  ))}
                </div>
                
                <div className="action-items">
                  <h4>Must-Do Actions</h4>
                  <ul>
                    {results.vulnerabilities_summary.slice(0, 3).map((vuln, idx) => (
                      <li key={idx}>Fix: {vuln.name}</li>
                    ))}
                  </ul>
                </div>
              </>
            ) : (
              <p className="placeholder">No vulnerabilities detected</p>
            )}
          </div>
        </div>
      )}

      {!results && !loading && !error && (
        <div className="empty-state">
          <div className="empty-icon">🔒</div>
          <h3>Ready to Scan</h3>
          <p>Click "Run Security Scan" to analyze your network for vulnerabilities</p>
        </div>
      )}
    </div>
  )
}

export default App