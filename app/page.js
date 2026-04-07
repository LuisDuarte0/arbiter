'use client'
import { useState } from 'react'
import Header from './components/Header'
import AlertQueue from './components/AlertQueue'
import AnalysisPanel from './components/AnalysisPanel'
import IntelPanel from './components/IntelPanel'

export default function Home() {
  const [alertText, setAlertText]           = useState('')
  const [result, setResult]                 = useState(null)
  const [loading, setLoading]               = useState(false)
  const [error, setError]                   = useState(null)
  const [activeId, setActiveId]             = useState(null)
  const [history, setHistory] = useState(() => {
    try {
      const stored = JSON.parse(localStorage.getItem('arbiter_history') ?? '[]')
      return stored.map(item => ({ ...item, timestamp: new Date(item.timestamp) }))
    } catch { return [] }
  })
  const [queueCollapsed, setQueueCollapsed] = useState(false)
  const [intelCollapsed, setIntelCollapsed] = useState(false)

  function handleReset() {
    setAlertText('')
    setResult(null)
    setError(null)
    setActiveId(null)
  }

  function handleSelectHistory(item) {
    setActiveId(item.id)
    setResult(item.fullResult)
    setAlertText(item.alertText)
    setError(null)
  }

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

      const newEntry = {
        id: newId,
        timestamp: new Date(),
        classification: data.triage.classification,
        severity: data.triage.severity,
        tactic: data.triage.tactic,
        asset: data.triage.affected_asset,
        confidence: data.triage.confidence,
        fullResult: data,
        alertText: alertText,
      }
      setHistory(prev => {
        const updated = [newEntry, ...prev]
        try {
          localStorage.setItem('arbiter_history', JSON.stringify(updated.slice(0, 50)))
        } catch {}
        return updated
      })

      try {
        const existing = JSON.parse(localStorage.getItem('arbiter_audit') ?? '[]')
        const entry = {
          id: newId,
          timestamp: new Date().toISOString(),
          alertText,
          triage: data.triage,
          enrichment: data.enrichment,
          ips: data.ips,
          meta: data.meta,
        }
        localStorage.setItem('arbiter_audit', JSON.stringify([entry, ...existing].slice(0, 100)))
      } catch { /* localStorage unavailable */ }

    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const mainClass = [
    'arb-main',
    queueCollapsed && intelCollapsed ? 'arb-main-both-collapsed'
      : queueCollapsed ? 'arb-main-collapsed'
      : intelCollapsed ? 'arb-main-intel-collapsed'
      : '',
  ].filter(Boolean).join(' ')

  return (
    <div className="arb-layout">
      <Header activeId={activeId} result={result} onReset={handleReset} />
      <main className={mainClass}>
        <AlertQueue
          history={history}
          activeId={loading ? activeId : null}
          collapsed={queueCollapsed}
          onToggle={() => setQueueCollapsed(p => !p)}
          onSelect={handleSelectHistory}
        />
        <AnalysisPanel
          alertText={alertText}
          setAlertText={setAlertText}
          result={result}
          loading={loading}
          error={error}
          onTriage={handleTriage}
          onReset={handleReset}
        />
        <IntelPanel
          result={result}
          collapsed={intelCollapsed}
          onToggle={() => setIntelCollapsed(p => !p)}
        />
      </main>
    </div>
  )
}