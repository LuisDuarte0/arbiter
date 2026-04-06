'use client'
import { useState } from 'react'
import Header from './components/Header'
import AlertQueue from './components/AlertQueue'
import AnalysisPanel from './components/AnalysisPanel'
import IntelPanel from './components/IntelPanel'

export default function Home() {
  const [alertText, setAlertText] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [activeId, setActiveId] = useState(null)
  const [history, setHistory] = useState([])
  const [queueCollapsed, setQueueCollapsed] = useState(false)

  async function handleTriage() {
    if (!alertText.trim()) return
    const newId = `ARB-${Date.now()}`
    setLoading(true)
    setError(null)
    setResult(null)
    setActiveId(newId)

    try {
      const res = await fetch('/api/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alertText }),
      })
      const data = await res.json()
      if (data.error) throw new Error(data.error)
      setResult(data)
      setHistory(prev => [{
        id: newId,
        timestamp: new Date(),
        classification: data.triage.classification,
        severity: data.triage.severity,
        tactic: data.triage.tactic,
        asset: data.triage.affected_asset,
        confidence: data.triage.confidence,
      }, ...prev])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="arb-layout">
      <Header activeId={activeId} result={result} />
      <main className={`arb-main${queueCollapsed ? ' arb-main-collapsed' : ''}`}>
        <AlertQueue
          history={history}
          activeId={loading ? activeId : null}
          collapsed={queueCollapsed}
          onToggle={() => setQueueCollapsed(p => !p)}
        />
        <AnalysisPanel
          alertText={alertText}
          setAlertText={setAlertText}
          result={result}
          loading={loading}
          error={error}
          onTriage={handleTriage}
        />
        <IntelPanel result={result} />
      </main>
    </div>
  )
}