import { useState } from 'react'
import './App.css'

function App() {
  const [target, setTarget] = useState('localhost')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)

  const runScan = async () => {
    setLoading(true)
    try {
      const response = await fetch('http://localhost:8000/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target })
      })
      const data = await response.json()
      setResults(data)
    } catch (error) {
      console.error('Scan failed:', error)
      alert('Scan failed: ' + error.message)
    }
    setLoading(false)
  }

  return (
    <div className="App">
      <h1>🛡️ CyberSec AI Agent</h1>
      <p>AI-Powered Security Analysis for SMBs</p>
      
      <div className="scan-input">
        <input 
          type="text" 
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="Enter target IP or hostname"
          disabled={loading}
        />
        <button onClick={runScan} disabled={loading}>
          {loading ? 'Scanning...' : 'Run Security Scan'}
        </button>
      </div>

      {results && (
        <div className="results">
          <div className="section">
            <h2>🤖 AI Analysis</h2>
            <pre className="ai-output">{results.ai_analysis}</pre>
          </div>
          
          <details>
            <summary>View Raw Scanner Output</summary>
            <pre className="raw-output">{results.raw_output}</pre>
          </details>
        </div>
      )}
    </div>
  )
}

export default App