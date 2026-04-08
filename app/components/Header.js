'use client'
import { useState, useEffect } from 'react'
import AuditLog from './AuditLog'

function CoreIndicator() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
      <div style={{ position: 'relative', width: '10px', height: '10px' }}>
        <div style={{ position: 'absolute', inset: 0, background: '#00ff41', borderRadius: '2px', animation: 'arbCoreBreath 2.4s ease-in-out infinite' }} />
        <div style={{ position: 'absolute', inset: '2px', background: '#080C14', borderRadius: '1px' }} />
        <div style={{ position: 'absolute', inset: '3.5px', background: '#00ff41', borderRadius: '0.5px', animation: 'arbCoreInner 2.4s ease-in-out infinite' }} />
      </div>
      <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'rgba(0,255,65,0.5)', letterSpacing: '0.12em' }}>CORE: ACTIVE</span>
    </div>
  )
}

function AboutModal({ onClose }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(8,12,20,0.85)', zIndex: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }} onClick={onClose}>
      <div style={{ position: 'relative', background: 'var(--bg-card)', border: '0.5px solid var(--border-bright)', borderRadius: '6px', padding: '32px', width: '420px', maxWidth: '90vw' }} onClick={e => e.stopPropagation()}>
        <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)', letterSpacing: '0.18em', marginBottom: '20px' }}>ABOUT ARBITER</div>
        <div style={{ fontSize: '20px', fontWeight: '500', color: 'var(--text-primary)', marginBottom: '8px' }}>Luis Carlos Moreira Duarte</div>
        <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '10px', color: 'var(--amber)', marginBottom: '16px' }}>Detection Engineering · Tempest Security Intelligence</div>
        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.7', marginBottom: '20px' }}>
          ARBITER is an AI-powered SOC alert triage engine built to demonstrate real-world detection engineering — enrichment pipelines, LLM-based classification, temporal correlation via Redis, and MITRE ATT&CK coverage analysis.
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <a href="https://linkedin.com" target="_blank" rel="noreferrer" style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--amber)', letterSpacing: '0.08em', border: '0.5px solid var(--amber-40)', borderRadius: '3px', padding: '5px 12px', textDecoration: 'none' }}>LINKEDIN →</a>
          <a href="https://github.com/LuisDuarte0/arbiter" target="_blank" rel="noreferrer" style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-secondary)', letterSpacing: '0.08em', border: '0.5px solid var(--border-bright)', borderRadius: '3px', padding: '5px 12px', textDecoration: 'none' }}>GITHUB →</a>
        </div>
        <button onClick={onClose} style={{ position: 'absolute', top: '16px', right: '16px', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '14px' }}>✕</button>
      </div>
    </div>
  )
}

function MitrePanel({ onClose, onMitreFilter }) {
  const [logs, setLogs] = useState([])

  useState(() => {
    try { setLogs(JSON.parse(localStorage.getItem('arbiter_audit') ?? '[]')) }
    catch { setLogs([]) }
  })

  const techniques = {}
  logs.forEach(log => {
    const id = log.triage?.mitre_id
    if (!id) return
    if (!techniques[id]) techniques[id] = { id, name: log.triage?.mitre_name ?? id, tactic: log.triage?.mitre_tactic ?? '', count: 0, severities: [], assets: [] }
    techniques[id].count++
    techniques[id].severities.push(log.triage?.severity)
    if (log.triage?.affected_asset) techniques[id].assets.push(log.triage.affected_asset)
  })

  const techList = Object.values(techniques).sort((a, b) => b.count - a.count)
  const total = logs.length || 1
  const totalCritical = logs.filter(l => l.triage?.severity === 'CRITICAL').length
  const totalHigh     = logs.filter(l => l.triage?.severity === 'HIGH').length
  const totalMedium   = logs.filter(l => l.triage?.severity === 'MEDIUM').length
  const totalLow      = logs.filter(l => l.triage?.severity === 'LOW').length

  const assetCounts = {}
  logs.forEach(l => { const a = l.triage?.affected_asset; if (a) assetCounts[a] = (assetCounts[a] ?? 0) + 1 })
  const topAssets = Object.entries(assetCounts).sort((a, b) => b[1] - a[1]).slice(0, 5)

  return (
    <>
      <div style={{ position: 'fixed', inset: 0, background: 'rgba(8,12,20,0.5)', zIndex: 150 }} onClick={onClose} />
      <div style={{ position: 'fixed', top: 0, right: 0, bottom: 0, width: 'min(780px, 90vw)', background: 'var(--bg-panel)', borderLeft: '0.5px solid var(--border-bright)', zIndex: 151, display: 'flex', flexDirection: 'column', animation: 'arbSlideIn 0.2s ease-out' }}>

        <div style={{ padding: '18px 24px', borderBottom: '0.5px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
          <div>
            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)', letterSpacing: '0.18em', marginBottom: '4px' }}>MITRE ATT&CK INTELLIGENCE</div>
            <div style={{ fontSize: '18px', fontWeight: '500', color: 'var(--text-primary)' }}>Campaign Coverage</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: '0.5px solid var(--border-bright)', borderRadius: '3px', color: 'var(--text-muted)', cursor: 'pointer', padding: '5px 10px', fontFamily: 'var(--font-mono), monospace', fontSize: '9px' }}>CLOSE ✕</button>
        </div>

        <div style={{ padding: '14px 24px', borderBottom: '0.5px solid var(--border)', display: 'flex', gap: '24px', alignItems: 'center', flexShrink: 0 }}>
          {[
            { label: 'TOTAL ALERTS', value: logs.length, color: 'var(--text-primary)' },
            { label: 'TECHNIQUES', value: techList.length, color: 'var(--amber)' },
            { label: 'CRITICAL', value: totalCritical, color: 'var(--red)' },
            { label: 'HIGH', value: totalHigh, color: '#F59E0B' },
          ].map(s => (
            <div key={s.label}>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '3px' }}>{s.label}</div>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '22px', fontWeight: '600', color: s.color, lineHeight: 1 }}>{s.value}</div>
            </div>
          ))}
          <div style={{ marginLeft: 'auto', minWidth: '160px' }}>
            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: '4px' }}>SEVERITY MIX</div>
            <div style={{ height: '6px', background: 'var(--bg-input)', borderRadius: '2px', overflow: 'hidden', display: 'flex', marginBottom: '4px' }}>
              {[
                { pct: (totalCritical / total) * 100, color: 'var(--red)' },
                { pct: (totalHigh / total) * 100, color: '#F59E0B' },
                { pct: (totalMedium / total) * 100, color: '#6B7FD4' },
                { pct: (totalLow / total) * 100, color: 'var(--text-muted)' },
              ].map((s, i) => <div key={i} style={{ width: `${s.pct}%`, background: s.color }} />)}
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              {[['CRIT', totalCritical, 'var(--red)'], ['HIGH', totalHigh, '#F59E0B'], ['MED', totalMedium, '#6B7FD4'], ['LOW', totalLow, 'var(--text-muted)']].map(([l, v, c]) => (
                <span key={l} style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: c }}>{l}: {v}</span>
              ))}
            </div>
          </div>
        </div>

        <div style={{ flex: 1, overflow: 'hidden', display: 'grid', gridTemplateColumns: '1fr 220px' }}>
          <div style={{ overflowY: 'auto', padding: '16px 24px', borderRight: '0.5px solid var(--border)' }}>
            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '12px' }}>DETECTED TECHNIQUES — CLICK TO FILTER HISTORY</div>
            {techList.length === 0 && (
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '10px', color: 'var(--text-muted)', textAlign: 'center', paddingTop: '40px' }}>NO DETECTION DATA — RUN ANALYSES TO POPULATE</div>
            )}
            {techList.map(tech => {
              const hasCritical = tech.severities.includes('CRITICAL')
              const uniqueAssets = [...new Set(tech.assets)]
              return (
                <div key={tech.id} onClick={() => { onMitreFilter?.(tech.id); onClose() }}
                  style={{ padding: '10px 12px', marginBottom: '6px', background: hasCritical ? 'rgba(239,68,68,0.06)' : 'var(--bg-card)', border: `0.5px solid ${hasCritical ? 'rgba(239,68,68,0.3)' : 'var(--border-bright)'}`, borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '12px', transition: 'background 0.1s' }}
                  onMouseEnter={e => e.currentTarget.style.background = hasCritical ? 'rgba(239,68,68,0.12)' : 'var(--bg-input)'}
                  onMouseLeave={e => e.currentTarget.style.background = hasCritical ? 'rgba(239,68,68,0.06)' : 'var(--bg-card)'}
                >
                  <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '11px', color: 'var(--amber)', fontWeight: '600', minWidth: '80px' }}>{tech.id}</div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: '12px', fontWeight: '500', color: 'var(--text-primary)', marginBottom: '2px' }}>{tech.name}</div>
                    <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)' }}>{tech.tactic} · {uniqueAssets.length} asset{uniqueAssets.length !== 1 ? 's' : ''}</div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '3px' }}>
                    <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '16px', fontWeight: '600', color: tech.count >= 3 ? 'var(--red)' : 'var(--amber)', lineHeight: 1 }}>{tech.count}×</span>
                    {hasCritical && <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--red)', letterSpacing: '0.08em' }}>CRITICAL</span>}
                  </div>
                </div>
              )
            })}
          </div>

          <div style={{ overflowY: 'auto', padding: '16px' }}>
            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)', letterSpacing: '0.15em', marginBottom: '12px' }}>TOP TARGETED ASSETS</div>
            {topAssets.map(([asset, count], i) => (
              <div key={asset} style={{ marginBottom: '10px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '3px' }}>
                  <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: i === 0 ? 'var(--amber)' : 'var(--text-secondary)' }}>{asset}</span>
                  <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-muted)' }}>{count}</span>
                </div>
                <div style={{ height: '2px', background: 'var(--border-bright)', borderRadius: '1px', overflow: 'hidden' }}>
                  <div style={{ height: '100%', background: i === 0 ? 'var(--amber)' : 'var(--border-bright)', width: `${(count / (topAssets[0]?.[1] ?? 1)) * 100}%`, filter: i === 0 ? 'none' : 'brightness(2)' }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  )
}

export default function Header({ activeId, result, onReset, onMitreFilter }) {
  const [auditOpen,  setAuditOpen]  = useState(false)
  const [mitreOpen,  setMitreOpen]  = useState(false)
  const [aboutOpen,  setAboutOpen]  = useState(false)
  const [auditCount, setAuditCount] = useState(0)

  useEffect(() => {
    function updateCount() {
      try { setAuditCount(JSON.parse(localStorage.getItem('arbiter_audit') ?? '[]').length) }
      catch { setAuditCount(0) }
    }
    updateCount()
    window.addEventListener('storage', updateCount)
    return () => window.removeEventListener('storage', updateCount)
  }, [result])

  const ghostBtn = { background: 'none', border: '0.5px solid rgba(255,255,255,0.12)', borderRadius: '3px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono), monospace', fontSize: '9px', letterSpacing: '0.1em', cursor: 'pointer', padding: '5px 12px', transition: 'all 0.15s', whiteSpace: 'nowrap' }
  const solidBtn = { ...ghostBtn, background: 'var(--amber)', border: '0.5px solid var(--amber)', color: '#080C14', fontWeight: '600' }

  return (
    <>
      <style>{`
        @keyframes arbCoreBreath { 0%,100%{opacity:1;box-shadow:0 0 4px #00ff41}50%{opacity:0.4;box-shadow:0 0 1px #00ff41} }
        @keyframes arbCoreInner  { 0%,100%{opacity:1}50%{opacity:0.3} }
        @keyframes arbSlideIn    { from{transform:translateX(100%)}to{transform:translateX(0)} }
      `}</style>

      <header className="arb-header" style={{ justifyContent: 'space-between' }}>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexShrink: 0 }}>
          <div className="arb-logo">
            <svg viewBox="-8 0 136 120" width="26" height="22" xmlns="http://www.w3.org/2000/svg">
              <line x1="60" y1="8" x2="6" y2="112" stroke="#F59E0B" strokeWidth="17" strokeLinecap="square"/>
              <line x1="60" y1="8" x2="114" y2="112" stroke="#F59E0B" strokeWidth="17" strokeLinecap="square"/>
              <line x1="-6" y1="68" x2="126" y2="68" stroke="#F59E0B" strokeWidth="7" strokeLinecap="square"/>
            </svg>
            <span className="arb-wordmark">ARBITER</span>
          </div>
          <div className="arb-hdivider" />
          <div className="arb-hmeta">
            <div className="arb-case-id">{activeId ?? 'NO ACTIVE CASE'}</div>
            <div className="arb-case-sub">{result ? `${result.triage.tactic.toUpperCase()} · ANALYSIS COMPLETE` : 'AWAITING ALERT INPUT'}</div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          {result && (
            <button style={solidBtn} onClick={onReset}
              onMouseEnter={e => e.currentTarget.style.opacity = '0.85'}
              onMouseLeave={e => e.currentTarget.style.opacity = '1'}
            >NEW ANALYSIS</button>
          )}
          <button style={ghostBtn} onClick={() => setAuditOpen(true)}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; e.currentTarget.style.color = 'var(--text-primary)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'var(--text-secondary)' }}
          >
            AUDIT LOG
            {auditCount > 0 && <span style={{ marginLeft: '6px', background: 'var(--amber)', color: '#080C14', borderRadius: '2px', padding: '0 4px', fontSize: '8px', fontWeight: '700' }}>{auditCount}</span>}
          </button>
          <button style={ghostBtn} onClick={() => setMitreOpen(true)}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; e.currentTarget.style.color = 'var(--text-primary)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'var(--text-secondary)' }}
          >MITRE ATT&CK</button>
          <button style={{ ...ghostBtn, fontSize: '8px', padding: '5px 9px' }} onClick={() => setAboutOpen(true)}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; e.currentTarget.style.color = 'var(--text-primary)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'var(--text-secondary)' }}
          >i</button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexShrink: 0 }}>
          <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)', letterSpacing: '0.06em' }}>
            POWERED BY <span style={{ color: 'var(--text-secondary)' }}>GROQ · LLAMA 3.3</span>
          </div>
          <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)', letterSpacing: '0.06em' }}>
            BY <span style={{ color: 'var(--text-secondary)' }}>LUIS DUARTE</span>
          </div>
          <div className="arb-hdivider" />
          <CoreIndicator />
        </div>

      </header>

      {auditOpen && <AuditLog onClose={() => setAuditOpen(false)} onMitreFilter={onMitreFilter} />}
      {mitreOpen && <MitrePanel onClose={() => setMitreOpen(false)} onMitreFilter={onMitreFilter} />}
      {aboutOpen && <AboutModal onClose={() => setAboutOpen(false)} />}
    </>
  )
}