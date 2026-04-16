'use client'
import React, { useState, useEffect } from 'react'
import AuditLog from './AuditLog'
import AboutModal from './AboutModal'

// ── KEY CONSTANTS ──────────────────────────────────────────────────────────────
// Shared with AboutModal.js — must stay in sync if renamed
const AWAITING_KEY       = 'arbiter_about_awaiting_return'
// Set when user reaches the final page — only then does the button become normal
const ABOUT_COMPLETED_KEY = 'arbiter_about_completed'



function MitrePanel({ onClose, onMitreFilter, redisInsights }) {
  const [logs, setLogs] = React.useState([])
  const [localRedisInsights, setLocalRedisInsights] = React.useState(redisInsights)
  const [view, setView] = React.useState('timeline')
  const [tooltip, setTooltip] = React.useState(null)

  React.useEffect(() => {
    try { setLogs(JSON.parse(localStorage.getItem('arbiter_audit') ?? '[]')) }
    catch { setLogs([]) }
  }, [])

  React.useEffect(() => {
    async function fetchInsights() {
      try {
        const sessionId = sessionStorage.getItem('arbiter_session_id') ?? 'default'
        const res = await fetch(`/api/redis-insights?sessionId=${sessionId}`)
        const data = await res.json()
        setLocalRedisInsights(data)
      } catch {}
    }
    fetchInsights()
  }, [])

  const valid = logs.filter(l => l.triage?.mitre_id && l.timestamp)
  const total = logs.length
  const crit  = logs.filter(l => l.triage?.severity === 'CRITICAL').length
  const high  = logs.filter(l => l.triage?.severity === 'HIGH').length
  const med   = logs.filter(l => l.triage?.severity === 'MEDIUM').length
  const low   = logs.filter(l => l.triage?.severity === 'LOW').length

  const techMap = {}
  valid.forEach(l => {
    const id = l.triage.mitre_id
    if (!techMap[id]) techMap[id] = { id, name: l.triage.mitre_name ?? id, tactic: l.triage.mitre_tactic ?? '', count: 0, severities: [], assets: [], events: [] }
    techMap[id].count++
    techMap[id].severities.push(l.triage.severity)
    if (l.triage.affected_asset && l.triage.affected_asset !== 'UNKNOWN') techMap[id].assets.push(l.triage.affected_asset)
    techMap[id].events.push(l)
  })
  const techList = Object.values(techMap).sort((a, b) => b.count - a.count)
  const techsSorted = Object.values(techMap).sort((a, b) => {
    const ta = Math.min(...a.events.map(e => new Date(e.timestamp).getTime()))
    const tb = Math.min(...b.events.map(e => new Date(e.timestamp).getTime()))
    return ta - tb
  })

  const assetCounts = {}
  logs.forEach(l => { const a = l.triage?.affected_asset; if (a && a !== 'UNKNOWN') assetCounts[a] = (assetCounts[a] ?? 0) + 1 })
  const topAssets = Object.entries(assetCounts).sort((a, b) => b[1] - a[1]).slice(0, 6)

  const times = valid.map(l => new Date(l.timestamp).getTime())
  const tMin = times.length ? Math.min(...times) : 0
  const tMax = times.length ? Math.max(...times) : 1
  const tRange = tMax - tMin || 1

  const fmt = ts => new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' })
  const sevClass = s => ({ CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }[s] ?? 'low')
  const sevColor = s => ({ CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#EAB308', LOW: '#6B7280' }[s] ?? '#6B7280')

  const uniqueTactics = [...new Set(valid.map(l => l.triage.mitre_tactic).filter(Boolean))]
  const uniqueAssets = [...new Set(valid.map(l => l.triage.affected_asset).filter(a => a && a !== 'UNKNOWN'))]
  const firstEvent = valid.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))[0]
  const lastEvent = valid[valid.length - 1]
  const durationMin = firstEvent && lastEvent ? Math.round((new Date(lastEvent.timestamp) - new Date(firstEvent.timestamp)) / 60000) : 0

  const tickCount = 6
  const ticks = Array.from({ length: tickCount }, (_, i) => ({
    pct: (i / (tickCount - 1)) * 100,
    label: fmt(tMin + (i / (tickCount - 1)) * tRange)
  }))

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'var(--bg-base)', zIndex: 150, display: 'flex', flexDirection: 'column', animation: 'arbFadeIn 0.18s ease-out' }}>

      {/* HEADER */}
      <div style={{ padding: '16px 32px', borderBottom: '0.5px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0, background: 'var(--bg-panel)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
          <div>
            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'rgba(255,255,255,0.5)', letterSpacing: '0.18em', marginBottom: '3px' }}>MITRE ATT&CK INTELLIGENCE</div>
            <div style={{ fontSize: '18px', fontWeight: '500', color: 'var(--text-primary)' }}>Campaign Coverage</div>
          </div>
          <div style={{ width: '0.5px', height: '32px', background: 'var(--border-bright)' }} />
          <div style={{ display: 'flex', gap: '24px', alignItems: 'center' }}>
            {[
              { label: 'TOTAL ALERTS', value: total, color: 'var(--text-primary)' },
              { label: 'REDIS 24H', value: localRedisInsights?.totalHits ?? 0, color: (localRedisInsights?.totalHits ?? 0) > 0 ? 'var(--red)' : 'var(--text-muted)' },
              { label: 'TECHNIQUES', value: techList.length, color: 'var(--amber)' },
              { label: 'CRITICAL', value: crit, color: 'var(--red)' },
              { label: 'HIGH', value: high, color: 'var(--amber)' },
            ].map(s => (
              <div key={s.label}>
                <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'rgba(255,255,255,0.45)', letterSpacing: '0.12em', marginBottom: '2px' }}>{s.label}</div>
                <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '20px', fontWeight: '600', color: s.color, lineHeight: 1 }}>{s.value}</div>
              </div>
            ))}
            <div>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'rgba(255,255,255,0.45)', letterSpacing: '0.12em', marginBottom: '4px' }}>SEVERITY MIX</div>
              <div style={{ display: 'flex', height: '6px', width: '120px', borderRadius: '2px', overflow: 'hidden', background: 'var(--border)', marginBottom: '4px' }}>
                {[{ c: crit, col: '#EF4444' }, { c: high, col: '#F59E0B' }, { c: med, col: '#EAB308' }, { c: low, col: '#6B7280' }].map((s, i) => (
                  total > 0 && s.c > 0 ? <div key={i} style={{ flex: s.c, background: s.col }} /> : null
                ))}
              </div>
              <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: crit > 0 ? 'var(--red)' : 'var(--text-muted)' }}>CRIT: {crit}</span>
                <span style={{ color: 'var(--border-bright)', fontSize: '10px' }}>·</span>
                <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: high > 0 ? 'var(--amber)' : 'var(--text-muted)' }}>HIGH: {high}</span>
                <span style={{ color: 'var(--border-bright)', fontSize: '10px' }}>·</span>
                <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: med > 0 ? '#EAB308' : 'var(--text-muted)' }}>MED: {med}</span>
                <span style={{ color: 'var(--border-bright)', fontSize: '10px' }}>·</span>
                <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-muted)' }}>LOW: {low}</span>
              </div>
            </div>
          </div>
        </div>
        <button
          onClick={onClose}
          style={{
            background: 'none',
            border: '0.5px solid rgba(239,68,68,0.5)',
            borderRadius: '3px',
            color: 'rgba(239,68,68,0.8)',
            fontFamily: 'var(--font-mono), monospace',
            fontSize: '12px',
            cursor: 'pointer',
            padding: '3px 9px',
            lineHeight: 1,
            transition: 'all 0.15s',
            flexShrink: 0,
          }}
          onMouseEnter={e => {
            e.currentTarget.style.background = 'rgba(239,68,68,0.12)'
            e.currentTarget.style.borderColor = 'rgba(239,68,68,0.9)'
            e.currentTarget.style.color = '#EF4444'
          }}
          onMouseLeave={e => {
            e.currentTarget.style.background = 'none'
            e.currentTarget.style.borderColor = 'rgba(239,68,68,0.5)'
            e.currentTarget.style.color = 'rgba(239,68,68,0.8)'
          }}
        >✕</button>
      </div>

      {/* TOGGLE */}
      <div style={{ padding: '10px 32px', borderBottom: '0.5px solid var(--border)', display: 'flex', gap: '4px', background: 'var(--bg-panel)', flexShrink: 0 }}>
        <button onClick={() => setView('timeline')} style={{
          background: view === 'timeline' ? 'rgba(245,158,11,0.12)' : 'none',
          border: view === 'timeline' ? '0.5px solid rgba(245,158,11,0.6)' : '0.5px solid var(--border)',
          borderRadius: '3px',
          color: view === 'timeline' ? 'var(--amber)' : 'var(--text-muted)',
          fontFamily: 'var(--font-mono), monospace',
          fontSize: '8px',
          letterSpacing: '0.1em',
          cursor: 'pointer',
          padding: '4px 12px',
          fontWeight: view === 'timeline' ? '600' : '400',
          transition: 'all 0.15s',
        }}>ATTACK PROGRESSION</button>
        <button onClick={() => setView('aggregate')} style={{
          background: view === 'aggregate' ? 'rgba(245,158,11,0.12)' : 'none',
          border: view === 'aggregate' ? '0.5px solid rgba(245,158,11,0.6)' : '0.5px solid var(--border)',
          borderRadius: '3px',
          color: view === 'aggregate' ? 'var(--amber)' : 'var(--text-muted)',
          fontFamily: 'var(--font-mono), monospace',
          fontSize: '8px',
          letterSpacing: '0.1em',
          cursor: 'pointer',
          padding: '4px 12px',
          fontWeight: view === 'aggregate' ? '600' : '400',
          transition: 'all 0.15s',
        }}>TECHNIQUE SUMMARY</button>
      </div>

      {/* BODY */}
      <div style={{ flex: 1, overflow: 'hidden', display: 'grid', gridTemplateColumns: '1fr 260px' }}>

        {/* LEFT — MAIN CONTENT */}
        <div style={{ overflowY: 'auto', borderRight: '0.5px solid var(--border)' }}>

          {/* TIMELINE VIEW */}
          {view === 'timeline' && (
            <div style={{ padding: '24px 32px' }}>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'rgba(255,255,255,0.5)', letterSpacing: '0.18em', marginBottom: '20px' }}>
                TECHNIQUE × TIME — hover to inspect
              </div>

              {valid.length === 0 ? (
                <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '10px', color: 'var(--text-muted)', textAlign: 'center', paddingTop: '60px', letterSpacing: '0.1em' }}>
                  NO DETECTION DATA — RUN ANALYSES TO POPULATE
                </div>
              ) : (
                <>
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    {techsSorted.map(tech => {
                      const hasCrit = tech.severities.includes('CRITICAL')
                      return (
                        <div key={tech.id} className="mitre-tl-row">
                          <div style={{ width: '120px', flexShrink: 0, paddingRight: '16px' }}>
                            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '10px', color: '#F59E0B', letterSpacing: '0.06em' }}>{tech.id}</div>
                            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'rgba(255,255,255,0.35)', marginTop: '2px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '110px' }}>{tech.tactic}</div>
                          </div>
                          <div style={{ flex: 1, position: 'relative', height: '100%', display: 'flex', alignItems: 'center' }}>
                            <div style={{ position: 'absolute', left: 0, right: 0, height: '0.5px', background: '#1E2D44' }} />
                            {tech.events.map((ev, i) => {
                              const t = new Date(ev.timestamp).getTime()
                              const pct = ((t - tMin) / tRange) * 96 + 2
                              const sev = ev.triage.severity
                              return (
                                <div key={i}
                                  style={{ position: 'absolute', left: `${pct}%`, transform: 'translateX(-50%)', zIndex: 2, display: 'flex', flexDirection: 'column', alignItems: 'center' }}
                                  onMouseEnter={e => {
                                    const rect = e.currentTarget.getBoundingClientRect()
                                    setTooltip({ ev, x: rect.left + 14, y: rect.top - 10 })
                                  }}
                                  onMouseLeave={() => setTooltip(null)}
                                >
                                  <div className={`mitre-tl-dot ${sevClass(sev)}`} />
                                </div>
                              )
                            })}
                          </div>
                          <div style={{ width: '60px', textAlign: 'right', flexShrink: 0 }}>
                            <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '13px', fontWeight: '500', color: hasCrit ? '#EF4444' : '#F59E0B' }}>{tech.count}×</span>
                          </div>
                        </div>
                      )
                    })}
                  </div>

                  {/* TIME AXIS */}
                  <div style={{ display: 'flex', paddingLeft: '120px', paddingRight: '60px', marginTop: '8px', position: 'relative', height: '24px' }}>
                    <div style={{ position: 'absolute', left: '120px', right: '60px', top: 0, height: '0.5px', background: '#1E2D44' }} />
                    {ticks.map((tick, i) => (
                      <div key={i} style={{ position: 'absolute', left: `calc(120px + ${tick.pct}% * (100% - 120px - 60px) / 100)`, transform: 'translateX(-50%)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '2px' }}>
                        <div style={{ width: '0.5px', height: '4px', background: '#1E2D44' }} />
                        <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: '#334055', whiteSpace: 'nowrap', letterSpacing: '0.04em' }}>{tick.label}</div>
                      </div>
                    ))}
                  </div>

                  {/* LEGEND */}
                  <div style={{ display: 'flex', gap: '20px', marginTop: '20px', paddingTop: '16px', borderTop: '0.5px solid var(--border)' }}>
                    {[['CRITICAL', '#EF4444'], ['HIGH', '#F59E0B'], ['MEDIUM', '#EAB308'], ['LOW', '#6B7280']].map(([l, c]) => (
                      <div key={l} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <div style={{ width: '8px', height: '8px', borderRadius: '50%', border: `1.5px solid ${c}`, background: c + '22' }} />
                        <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'rgba(255,255,255,0.4)', letterSpacing: '0.08em' }}>{l}</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          )}

          {/* AGGREGATE VIEW */}
          {view === 'aggregate' && (
            <div style={{ padding: '24px 32px' }}>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'rgba(255,255,255,0.5)', letterSpacing: '0.18em', marginBottom: '20px' }}>
                SESSION ACTIVITY — CLICK TO FILTER HISTORY
              </div>
              {techList.length === 0 && (
                <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '10px', color: 'var(--text-muted)', textAlign: 'center', paddingTop: '60px', letterSpacing: '0.1em' }}>NO DETECTION DATA — RUN ANALYSES TO POPULATE</div>
              )}
              {techList.map(tech => {
                const hasCritical = tech.severities.includes('CRITICAL')
                const uniqueAssets = [...new Set(tech.assets)]
                return (
                  <div key={tech.id}
                    onClick={() => { onMitreFilter?.(tech.id); onClose() }}
                    style={{ padding: '12px 16px', marginBottom: '6px', background: hasCritical ? 'rgba(239,68,68,0.06)' : 'var(--bg-card)', border: `0.5px solid ${hasCritical ? 'rgba(239,68,68,0.3)' : 'var(--border-bright)'}`, borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '16px', transition: 'background 0.1s' }}
                    onMouseEnter={e => e.currentTarget.style.background = hasCritical ? 'rgba(239,68,68,0.12)' : 'var(--bg-input)'}
                    onMouseLeave={e => e.currentTarget.style.background = hasCritical ? 'rgba(239,68,68,0.06)' : 'var(--bg-card)'}
                  >
                    <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '11px', color: 'var(--amber)', fontWeight: '600', minWidth: '80px' }}>{tech.id}</div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '13px', fontWeight: '500', color: 'var(--text-primary)', marginBottom: '3px' }}>{tech.name}</div>
                      <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)' }}>{tech.tactic} · {uniqueAssets.slice(0, 3).join(', ')}{uniqueAssets.length > 3 ? ` +${uniqueAssets.length - 3}` : ''}</div>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '3px' }}>
                      <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '18px', fontWeight: '600', color: tech.count >= 3 ? 'var(--red)' : 'var(--amber)', lineHeight: 1 }}>{tech.count}×</span>
                      {hasCritical && <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--red)', letterSpacing: '0.08em' }}>CRITICAL</span>}
                    </div>
                  </div>
                )
              })}

              {/* CORRELATED INTELLIGENCE */}
              <div style={{ marginTop: '28px', paddingTop: '18px', borderTop: '0.5px solid var(--border)' }}>
                <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'rgba(255,255,255,0.5)', letterSpacing: '0.18em', marginBottom: '20px' }}>
                  CORRELATED INTELLIGENCE (24H REDIS MEMORY) — CLICK TO FILTER HISTORY
                </div>
                {localRedisInsights?.indicators?.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    {localRedisInsights.indicators.slice(0, 8).map((ind, i) => {
                      const isIp = ind.key?.startsWith('ip:')
                      const label = isIp ? ind.key.slice(3) : ind.key?.slice(5)?.replace(/_/g, ' ')
                      const labelColor = isIp
                        ? (ind.count >= 3 ? 'var(--red)' : '#64B5F6')
                        : (ind.count >= 3 ? '#E57373' : '#CE93D8')
                      const assetList = (ind.assets ?? []).join(', ')
                      const assetDisplay = assetList.length > 45 ? assetList.slice(0, 45) + '…' : assetList
                      const severityColor = ind.severity === 'CRITICAL' ? 'var(--red)'
                        : ind.severity === 'HIGH' ? 'var(--amber)'
                        : 'var(--text-muted)'
                      return (
                        <div
                          key={i}
                          style={{
                            padding: '8px 10px',
                            marginBottom: '5px',
                            background: ind.count >= 3 ? 'rgba(229,115,115,0.06)' : 'var(--bg-card)',
                            border: '0.5px solid var(--border-bright)',
                            borderRadius: '3px',
                            cursor: 'pointer',
                            transition: 'background 0.15s, border-color 0.15s',
                          }}
                          onMouseEnter={e => {
                            e.currentTarget.style.background = ind.count >= 3
                              ? 'rgba(229,115,115,0.12)'
                              : 'rgba(255,255,255,0.04)'
                            e.currentTarget.style.borderColor = labelColor
                          }}
                          onMouseLeave={e => {
                            e.currentTarget.style.background = ind.count >= 3
                              ? 'rgba(229,115,115,0.06)'
                              : 'var(--bg-card)'
                            e.currentTarget.style.borderColor = 'var(--border-bright)'
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3px' }}>
                            <span style={{
                              fontFamily: 'var(--font-mono), monospace',
                              fontSize: '10px',
                              fontWeight: '600',
                              color: labelColor,
                              letterSpacing: '0.04em',
                            }}>{label}</span>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span style={{
                                fontFamily: 'var(--font-mono), monospace',
                                fontSize: '8px',
                                color: severityColor,
                                letterSpacing: '0.06em',
                              }}>{ind.severity}</span>
                              <span style={{
                                fontFamily: 'var(--font-mono), monospace',
                                fontSize: '11px',
                                fontWeight: '600',
                                color: ind.count >= 3 ? '#E57373' : 'var(--amber)',
                              }}>{ind.count}×</span>
                            </div>
                          </div>
                          {assetDisplay && (
                            <div style={{
                              fontFamily: 'var(--font-mono), monospace',
                              fontSize: '8px',
                              color: 'var(--text-muted)',
                              letterSpacing: '0.04em',
                              lineHeight: 1.4,
                            }}>{assetDisplay}</div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-muted)', textAlign: 'center', padding: '24px 0', letterSpacing: '0.08em' }}>NO CORRELATED INTELLIGENCE IN LAST 24H</div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* RIGHT SIDEBAR */}
        <div style={{ overflowY: 'auto', padding: '24px 20px', background: 'var(--bg-panel)' }}>

          {/* TOP TARGETED ASSETS */}
          <div style={{ marginBottom: '28px' }}>
            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'rgba(255,255,255,0.5)', letterSpacing: '0.18em', marginBottom: '14px' }}>TOP TARGETED ASSETS</div>
            {topAssets.length === 0 && <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-muted)' }}>—</div>}
            {topAssets.map(([asset, count], i) => (
              <div key={asset} style={{ marginBottom: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: i === 0 ? 'var(--amber)' : 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '160px' }}>{asset}</span>
                  <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-muted)', flexShrink: 0, marginLeft: '8px' }}>{count}×</span>
                </div>
                <div style={{ height: '2px', background: 'var(--border)', borderRadius: '1px', overflow: 'hidden' }}>
                  <div style={{ height: '100%', background: i === 0 ? 'var(--amber)' : 'var(--border-bright)', width: `${Math.round((count / (topAssets[0]?.[1] ?? 1)) * 100)}%`, opacity: i === 0 ? 1 : 0.6 }} />
                </div>
              </div>
            ))}
          </div>

          {/* ATTACK NARRATIVE */}
          {valid.length > 0 && (
            <div style={{ paddingTop: '20px', borderTop: '0.5px solid var(--border)' }}>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'rgba(255,255,255,0.5)', letterSpacing: '0.18em', marginBottom: '14px' }}>ATTACK NARRATIVE</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {[
                  { text: `${uniqueTactics.length} tactic${uniqueTactics.length !== 1 ? 's' : ''} observed`, sub: uniqueTactics.slice(0, 2).join(', ') + (uniqueTactics.length > 2 ? ` +${uniqueTactics.length - 2}` : '') },
                  { text: `${crit} CRITICAL event${crit !== 1 ? 's' : ''} detected`, sub: null },
                  { text: `First detection`, sub: firstEvent ? fmt(firstEvent.timestamp) : '—' },
                  { text: `Active duration`, sub: durationMin > 0 ? `${durationMin} min` : '<1 min' },
                  { text: `${uniqueAssets.length} unique asset${uniqueAssets.length !== 1 ? 's' : ''} targeted`, sub: null },
                ].map((item, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                    <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: i === 0 ? 'var(--amber)' : i === 1 ? (item.text.includes('CRITICAL') ? '#E57373' : 'var(--amber)') : 'var(--text-muted)', flexShrink: 0, marginTop: '4px' }} />
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>{item.text}</div>
                      {item.sub && <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)', marginTop: '1px', letterSpacing: '0.04em' }}>{item.sub}</div>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* TOOLTIP */}
      {tooltip && (
        <div style={{ position: 'fixed', left: tooltip.x, top: tooltip.y, background: 'var(--bg-card)', border: '0.5px solid var(--border-bright)', borderRadius: '4px', padding: '10px 12px', fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-muted)', zIndex: 200, pointerEvents: 'none', minWidth: '200px' }}>
          <div style={{ color: '#F59E0B', fontSize: '10px', marginBottom: '2px', letterSpacing: '0.06em' }}>{tooltip.ev.triage.mitre_id}</div>
          <div style={{ fontSize: '11px', color: 'var(--text-primary)', marginBottom: '8px', fontFamily: 'sans-serif', fontWeight: '500' }}>{tooltip.ev.triage.mitre_name}</div>
          {[
            ['TIME', fmt(tooltip.ev.timestamp)],
            ['SEVERITY', tooltip.ev.triage.severity],
            ['ASSET', tooltip.ev.triage.affected_asset || '—'],
            ['CONFIDENCE', tooltip.ev.triage.confidence ? `${tooltip.ev.triage.confidence}%` : '—'],
            ['CLASSIFICATION', tooltip.ev.triage.classification || '—'],
          ].map(([k, v]) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', gap: '16px', marginBottom: '2px' }}>
              <span style={{ color: 'var(--text-muted)' }}>{k}</span>
              <span style={{ color: k === 'SEVERITY' ? sevColor(tooltip.ev.triage.severity) : 'var(--text-secondary)' }}>{v}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── HEADER COMPONENT ──────────────────────────────────────────────────────────
export default function Header({ activeId, result, onReset, onMitreFilter, redisInsights, onClearHistory }) {
  const [auditOpen,  setAuditOpen]  = useState(false)
  const [mitreOpen,  setMitreOpen]  = useState(false)
  const [aboutOpen,  setAboutOpen]  = useState(false)
  const [auditCount, setAuditCount] = useState(0)

  // ── ABOUT button state machine ───────────────────────────────────────────────
  // State A (default): button is the hero — amber, breathing. Persists until
  // the user finishes the full walkthrough and reaches the final page.
  // Not based on "first visit" — every session starts with ABOUT prominent.
  // aboutCompleted: true only after the user has reached the final page.
  const [aboutCompleted, setAboutCompleted] = useState(false)

  // State B: true after user clicks LOAD AND ANALYZE in the modal.
  // Cleared when the user reaches the final page (same event that sets completed).
  // Drives the strong amber pulse — persists through all storytelling cards.
  const [aboutAwaitingReturn, setAboutAwaitingReturn] = useState(false)

  // Hydrate from localStorage after mount — keeps SSR/client first render identical.
  useEffect(() => {
    try {
      setAboutCompleted(!!localStorage.getItem(ABOUT_COMPLETED_KEY))
      setAboutAwaitingReturn(!!localStorage.getItem(AWAITING_KEY))
    } catch {}
  }, [])

  // Listen for same-tab awaiting-return events (from AboutModal.js)
  // and cross-tab storage events
  useEffect(() => {
    function check() {
      try { setAboutAwaitingReturn(!!localStorage.getItem(AWAITING_KEY)) } catch {}
    }
    check()
    window.addEventListener('storage', check)
    window.addEventListener('arbiter:about-awaiting', check)
    return () => {
      window.removeEventListener('storage', check)
      window.removeEventListener('arbiter:about-awaiting', check)
    }
  }, [])

  // When the user reaches the final page, AboutModal dispatches arbiter:about-completed.
  // At that point: awaiting return clears AND button transitions to State C (normal).
  useEffect(() => {
    function onCompleted() {
      setAboutAwaitingReturn(false)
      setAboutCompleted(true)
    }
    window.addEventListener('arbiter:about-completed', onCompleted)
    return () => window.removeEventListener('arbiter:about-completed', onCompleted)
  }, [])

  function openAbout() {
    setAboutOpen(true)
    // Opening the modal does NOT change the button state.
    // State A persists until the user finishes the walkthrough.
    // State B (awaiting return) is cleared only when reaching the final page.
  }

  useEffect(() => {
    function updateCount() {
      try { setAuditCount(JSON.parse(localStorage.getItem('arbiter_audit') ?? '[]').length) }
      catch { setAuditCount(0) }
    }
    updateCount()
    window.addEventListener('storage', updateCount)
    return () => window.removeEventListener('storage', updateCount)
  }, [result])

  // ── ABOUT button visual states ───────────────────────────────────────────────
  const ghostBtn = {
    background: 'none',
    border: '0.5px solid rgba(255,255,255,0.12)',
    borderRadius: '3px',
    color: 'var(--text-secondary)',
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '9px',
    letterSpacing: '0.1em',
    cursor: 'pointer',
    padding: '5px 12px',
    transition: 'all 0.15s',
    whiteSpace: 'nowrap',
  }
  const solidBtn = { ...ghostBtn, background: 'var(--amber)', border: '0.5px solid var(--amber)', color: '#080C14', fontWeight: '600' }

  function getAboutBtnStyle() {
    if (aboutAwaitingReturn) {
      // State B — strong amber pulse: user must return here
      return {
        ...ghostBtn,
        background: 'var(--amber)',
        border: '0.5px solid var(--amber)',
        color: '#080C14',
        fontWeight: '700',
        position: 'relative',
        animation: 'arbAboutReturn 1.0s ease-in-out infinite',
        transition: 'none',
      }
    }
    if (!aboutCompleted) {
      return {
        ...ghostBtn,
        background: 'rgba(245,158,11,0.07)',
        border: '0.5px solid rgba(245,158,11,0.6)',
        color: 'var(--amber)',
        position: 'relative',
        animation: 'arbAboutBreath 2.6s ease-in-out infinite',
        transition: 'none',
        fontWeight: '600',
      }
    }
    // State C — walkthrough complete, same appearance as AUDIT LOG and MITRE ATT&CK
    return { ...ghostBtn, position: 'relative' }
  }

  const isAboutSpecial = aboutAwaitingReturn || !aboutCompleted

  return (
    <>
      <style>{`
        @keyframes arbSlideIn  { from{transform:translateX(100%)}to{transform:translateX(0)} }
        @keyframes arbFadeIn   { from{opacity:0}to{opacity:1} }
        @keyframes arbDotPulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.4;transform:scale(0.8)} }

        /* State A — cold/first visit: border breathes in and out */
        @keyframes arbAboutBreath {
          0%,100% { box-shadow: 0 0 0 0 rgba(245,158,11,0);   border-color: rgba(245,158,11,0.4); }
          50%      { box-shadow: 0 0 14px 3px rgba(245,158,11,0.15); border-color: rgba(245,158,11,0.9); }
        }

        /* State B — awaiting return: amber fill pulses with outer glow */
        @keyframes arbAboutReturn {
          0%,100% { opacity: 1;    box-shadow: 0 0 0 0   rgba(245,158,11,0.5);  }
          50%      { opacity: 0.88; box-shadow: 0 0 18px 5px rgba(245,158,11,0.28); }
        }

        .mitre-tl-row { display:flex;align-items:center;height:48px;border-bottom:0.5px solid #151E2E;position:relative; }
        .mitre-tl-row:last-child { border-bottom:none; }
        .mitre-tl-dot { width:10px;height:10px;border-radius:50%;border:1.5px solid;background:#080C14;transition:transform 0.15s;cursor:pointer;flex-shrink:0; }
        .mitre-tl-dot:hover { transform:scale(1.5); }
        .mitre-tl-dot.critical { border-color:#EF4444;background:rgba(239,68,68,0.15); }
        .mitre-tl-dot.high     { border-color:#F59E0B;background:rgba(245,158,11,0.15); }
        .mitre-tl-dot.medium   { border-color:#EAB308;background:rgba(234,179,8,0.15); }
        .mitre-tl-dot.low      { border-color:#6B7280;background:rgba(107,114,128,0.15); }
      `}</style>

      <header className="arb-header" style={{ justifyContent: 'space-between', position: 'relative' }}>

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
            <div className="arb-case-sub">{result ? `${(result.triage.mitre_tactic ?? 'UNKNOWN').toUpperCase()} · ANALYSIS COMPLETE` : 'AWAITING ALERT INPUT'}</div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', position: 'absolute', left: '50%', transform: 'translateX(-50%)' }}>
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

          {/* ABOUT — three visual states: first-visit, awaiting-return, normal */}
          <button
            style={getAboutBtnStyle()}
            onClick={openAbout}
            {...(!isAboutSpecial ? {
              onMouseEnter: e => { e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; e.currentTarget.style.color = 'var(--text-secondary)' },
              onMouseLeave: e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'var(--text-secondary)' },
            } : {})}
          >
            ABOUT
          </button>
        </div>

      </header>

      {auditOpen && <AuditLog onClose={() => setAuditOpen(false)} onMitreFilter={onMitreFilter} onClearHistory={onClearHistory} />}
      {mitreOpen && <MitrePanel onClose={() => setMitreOpen(false)} onMitreFilter={onMitreFilter} redisInsights={redisInsights} />}
      {aboutOpen && <AboutModal onClose={() => setAboutOpen(false)} />}
    </>
  )
}