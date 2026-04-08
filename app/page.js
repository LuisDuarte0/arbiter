'use client'
import { useState, useEffect } from 'react'
import Header from './components/Header'
import AlertQueue from './components/AlertQueue'
import AnalysisPanel from './components/AnalysisPanel'
import IntelPanel from './components/IntelPanel'

export default function Home() {
  const [alertText, setAlertText]           = useState('')
  const [result, setResult]                 = useState(null)
  const [loading, setLoading]               = useState(false)
  const [loadingPhase, setLoadingPhase]     = useState('') // 'enriching' | 'analyzing'
  const [error, setError]                   = useState(null)
  const [activeId, setActiveId]             = useState(null)
  const [history, setHistory]               = useState([])
  const [queueCollapsed, setQueueCollapsed] = useState(false)
  const [intelCollapsed, setIntelCollapsed] = useState(false)
  const [mitreFilter, setMitreFilter]       = useState(null)
  const [indicatorCache, setIndicatorCache] = useState({})

  // Partial state — intel panel populates as soon as enrichment streams in
  const [streamedEnrichment, setStreamedEnrichment] = useState(null)
  const [streamedIPs, setStreamedIPs]               = useState([])

  useEffect(() => {
    try {
      const stored = JSON.parse(localStorage.getItem('arbiter_history') ?? '[]')
      setHistory(stored.map(item => ({ ...item, timestamp: new Date(item.timestamp) })))
    } catch {}
  }, [])

  function handleReset() {
    setAlertText('')
    setResult(null)
    setError(null)
    setActiveId(null)
    setStreamedEnrichment(null)
    setStreamedIPs([])
    setLoadingPhase('')
  }

  function handleSelectHistory(item) {
    setActiveId(item.id)
    setResult(item.fullResult)
    setAlertText(item.alertText)
    setError(null)
    setStreamedEnrichment(null)
    setStreamedIPs([])
  }

  async function handleTriage() {
    if (!alertText.trim()) return
    const newId = `ARB-${Date.now()}`
    setLoading(true)
    setError(null)
    setResult(null)
    setActiveId(newId)
    setStreamedEnrichment(null)
    setStreamedIPs([])
    setLoadingPhase('enriching')

    try {
      const res = await fetch('/api/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alertText }),
      })

      if (!res.ok || !res.body) {
        const data = await res.json()
        throw new Error(data.error ?? 'Triage failed.')
      }

      const reader  = res.body.getReader()
      const decoder = new TextDecoder()
      let   buffer  = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const parts = buffer.split('\n\n')
        buffer = parts.pop() ?? ''

        for (const part of parts) {
          if (!part.trim()) continue

          const eventMatch = part.match(/^event: (\w+)/m)
          const dataMatch  = part.match(/^data: (.+)$/m)

          if (!eventMatch || !dataMatch) continue

          const event = eventMatch[1]
          let payload
          try { payload = JSON.parse(dataMatch[1]) }
          catch { continue }

          if (event === 'status') {
            setLoadingPhase(payload.phase)
          }

          if (event === 'enrichment') {
            // Intel panel populates immediately — LLM still running
            setStreamedEnrichment(payload.enrichment)
            setStreamedIPs(payload.ips)
            setLoadingPhase('analyzing')
          }

          if (event === 'triage') {
            const data = payload
            setResult(data)
            if (data.ips?.length) {
  setIndicatorCache(prev => {
    const updated = { ...prev }
    data.ips.forEach(ip => {
      if (data.enrichment?.[ip]) {
        updated[ip] = {
          ...data.enrichment[ip],
          firstSeen: prev[ip]?.firstSeen ?? new Date().toISOString(),
          seenCount: (prev[ip]?.seenCount ?? 0) + 1,
          lastClassification: data.triage.classification,
        }
      }
    })
    return updated
  })
}
            setStreamedEnrichment(null) // result now has full enrichment
            setStreamedIPs([])

            const newEntry = {
              id: newId,
              timestamp: new Date(),
              classification: data.triage.classification,
              severity:       data.triage.severity,
              tactic:         data.triage.tactic,
              asset:          data.triage.affected_asset,
              confidence:     data.triage.confidence,
              fullResult:     data,
              alertText,
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
                id:         newId,
                timestamp:  new Date().toISOString(),
                alertText,
                triage:     data.triage,
                enrichment: data.enrichment,
                ips:        data.ips,
                meta:       data.meta,
              }
              localStorage.setItem('arbiter_audit', JSON.stringify([entry, ...existing].slice(0, 100)))
            } catch {}
          }

          if (event === 'error') {
            throw new Error(payload.message)
          }
        }
      }

    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
      setLoadingPhase('')
    }
  }

  const mainClass = [
    'arb-main',
    queueCollapsed && intelCollapsed ? 'arb-main-both-collapsed'
      : queueCollapsed ? 'arb-main-collapsed'
      : intelCollapsed ? 'arb-main-intel-collapsed'
      : '',
  ].filter(Boolean).join(' ')

  // Intel panel gets enrichment as soon as it streams, before triage completes
  const intelResult = result ?? (streamedEnrichment ? {
    enrichment: streamedEnrichment,
    ips: streamedIPs,
    triage: null,
  } : null)

  return (
    <div className="arb-layout">
      <Header activeId={activeId} result={result} onReset={handleReset} onMitreFilter={setMitreFilter} />
      <main className={mainClass}>
        <AlertQueue
  history={history}
  activeId={loading ? activeId : null}
  collapsed={queueCollapsed}
  onToggle={() => setQueueCollapsed(p => !p)}
  onSelect={handleSelectHistory}
  mitreFilter={mitreFilter}
  onMitreFilter={setMitreFilter}
/>
        <AnalysisPanel
          alertText={alertText}
          setAlertText={setAlertText}
          result={result}
          loading={loading}
          loadingPhase={loadingPhase}
          error={error}
          onTriage={handleTriage}
          onReset={handleReset}
        />
        <IntelPanel
  result={intelResult}
  collapsed={intelCollapsed}
  onToggle={() => setIntelCollapsed(p => !p)}
  indicatorCache={indicatorCache}
/>
      </main>
    </div>
  )
}