'use client'
import { useState } from 'react'

function formatTime(ts) {
  const d = new Date(ts)
  return d.toLocaleTimeString('en-US', { hour12: false }) + ' · ' + d.toLocaleDateString('en-GB')
}

export default function AuditLog({ onClose, onMitreFilter, onClearHistory }) {
  const [selected, setSelected] = useState(0)
  const logs = (() => {
    try { return JSON.parse(localStorage.getItem('arbiter_audit') ?? '[]') }
    catch { return [] }
  })()

  function exportAll() {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type:'application/json' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = `arbiter-audit-${Date.now()}.json`; a.click()
  }

  function exportOne() {
    const e = logs[selected]
    const blob = new Blob([JSON.stringify(e, null, 2)], { type:'application/json' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = `arbiter-${e.id}.json`; a.click()
  }

  async function exportPDF() {
    const { exportToPDF } = await import('./ExportPDF')
    await exportToPDF({ ...entry, id: entry.id }, entry.alertText)
  }

  function handleClearAll() {
    localStorage.removeItem('arbiter_audit')
    localStorage.removeItem('arbiter_history')
    onClearHistory?.()
    window.dispatchEvent(new Event('storage'))
    onClose()
  }

  if (!logs.length) return (
    <div className="arb-modal-overlay" onClick={onClose}>
      <div className="arb-modal" onClick={e => e.stopPropagation()}>
        <div className="arb-modal-header">
          <span className="arb-panel-title">AUDIT LOG</span>
          <button className="arb-audit-close" onClick={onClose}>✕</button>
        </div>
        <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'center' }}>
          <span className="arb-empty-text">No triage sessions recorded yet.</span>
        </div>
      </div>
    </div>
  )

  const entry = logs[selected]

  return (
    <div className="arb-modal-overlay" onClick={onClose}>
      <div className="arb-modal" onClick={e => e.stopPropagation()}>

        <div className="arb-modal-header">
          <div style={{ display:'flex', alignItems:'center', gap:'10px' }}>
            <span className="arb-panel-title">AUDIT LOG</span>
            <span className="arb-panel-badge">{logs.length} {logs.length === 1 ? 'ENTRY' : 'ENTRIES'}</span>
          </div>
          <div style={{ display:'flex', gap:'6px', alignItems:'center' }}>
            <button className="arb-audit-action-btn" onClick={exportOne}>EXPORT JSON</button>
            <button className="arb-audit-action-btn" onClick={exportAll}>EXPORT ALL</button>
            <button className="arb-audit-action-btn" onClick={exportPDF} style={{ color:'var(--amber)', borderColor:'var(--amber-40)' }}>EXPORT PDF</button>
            <button
              className="arb-audit-action-btn"
              onClick={handleClearAll}
              style={{ color: 'var(--red)', borderColor: 'rgba(239,68,68,0.4)' }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(239,68,68,0.1)' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'none' }}
            >
              CLEAR HISTORY
            </button>
            <button className="arb-audit-close" onClick={onClose}>✕</button>
          </div>
        </div>

        <div className="arb-modal-body">

          <div className="arb-modal-list">
            {logs.map((log, i) => (
              <div
                key={log.id}
                onClick={() => setSelected(i)}
                style={{
                  padding:'10px 14px',
                  borderBottom:'0.5px solid var(--border)',
                  cursor:'pointer',
                  background: i === selected ? 'var(--bg-card)' : 'none',
                  borderLeft: i === selected ? '2px solid var(--amber)' : '2px solid transparent',
                  paddingLeft: i === selected ? '12px' : '14px',
                  transition:'background 0.1s',
                }}
              >
                <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'4px' }}>
                  <span style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', color:'var(--text-muted)' }}>{log.id.slice(4,17)}</span>
                  <span className={`arb-badge arb-${log.triage.severity.toLowerCase()}`}>{log.triage.severity}</span>
                </div>
                <div style={{ fontSize:'12px', fontWeight:'500', color:'var(--text-primary)', marginBottom:'2px' }}>{log.triage.classification}</div>
                <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', color:'var(--text-secondary)', marginBottom:'1px' }}>{log.triage.affected_asset}</div>
                <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)' }}>{formatTime(log.timestamp)}</div>
              </div>
            ))}
          </div>

          <div className="arb-modal-detail">
            <div style={{ padding:'16px 20px', display:'flex', flexDirection:'column', gap:'14px' }}>

              <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', paddingBottom:'12px', borderBottom:'0.5px solid var(--border)' }}>
                <div>
                  <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', color:'var(--text-muted)', marginBottom:'6px' }}>{entry.id}</div>
                  <div style={{ fontSize:'18px', fontWeight:'500', color:'var(--text-primary)', marginBottom:'4px' }}>{entry.triage.classification}</div>
                  <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'10px', color:'var(--text-secondary)' }}>{entry.triage.tactic} · {entry.triage.mitre_id}</div>
                </div>
                <div style={{ textAlign:'right' }}>
                  <span className={`arb-badge arb-${entry.triage.severity.toLowerCase()}`}>{entry.triage.severity}</span>
                  <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'18px', fontWeight:'600', color:'var(--amber)', marginTop:'6px', lineHeight:1 }}>{entry.triage.confidence}<span style={{ fontSize:'10px', color:'var(--text-muted)' }}>%</span></div>
                  <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.1em' }}>CONFIDENCE</div>
                </div>
              </div>

              <div style={{ background:'var(--bg-card)', border:'0.5px solid var(--border-bright)', borderRadius:'5px', padding:'10px 12px' }}>
                <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em', marginBottom:'6px' }}>AFFECTED ASSET</div>
                <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'13px', fontWeight:'500', color:'var(--text-primary)', marginBottom:'4px' }}>{entry.triage.affected_asset}</div>
                {entry.triage.asset_is_critical && <span className="arb-asset-critical">CRITICAL ASSET</span>}
              </div>

              <div>
                <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em', textTransform:'uppercase', marginBottom:'6px' }}>ARBITER REASONING</div>
                <div style={{ background:'var(--bg-input)', borderLeft:'2px solid var(--amber)', borderRadius:'0 4px 4px 0', padding:'10px 14px', fontSize:'12px', color:'var(--text-secondary)', lineHeight:'1.75' }}>{Array.isArray(entry.triage.reasoning) ? entry.triage.reasoning.join(' ') : String(entry.triage.reasoning ?? '')}</div>
              </div>

            </div>

            {selected !== null && logs[selected] && (() => {
              const log = logs[selected]
              const isDeterministic = log.meta?.signals?.some(s => s.mitre)
              const isCorrelated = log.meta?.correlated
              return (
                <div style={{ borderTop: '0.5px solid var(--border)', padding: '14px 20px' }}>
                  <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.18em', color: 'var(--text-muted)', marginBottom: '10px' }}>MITRE ATT&CK</div>
                  {isCorrelated && (
                    <div style={{ background: 'rgba(229,115,115,0.08)', border: '0.5px solid rgba(229,115,115,0.3)', borderRadius: '3px', padding: '6px 10px', marginBottom: '10px', fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: '#E57373', letterSpacing: '0.08em' }}>
                      ▲ PART OF ACTIVE CAMPAIGN — seen across {Math.max(log.meta?.uniqueAssets ?? 0, 1)} asset{Math.max(log.meta?.uniqueAssets ?? 0, 1) !== 1 ? 's' : ''} in last 24h
                    </div>
                  )}
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '10px' }}>
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '13px', color: 'var(--amber)', fontWeight: '600', marginBottom: '3px' }}>{log.triage?.mitre_id}</div>
                      <div style={{ fontSize: '13px', fontWeight: '500', color: 'var(--text-primary)', marginBottom: '3px' }}>{log.triage?.mitre_name}</div>
                      <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-secondary)' }}>{log.triage?.mitre_tactic}</div>
                    </div>
                    <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: isDeterministic ? 'var(--amber)' : 'var(--text-muted)', background: isDeterministic ? 'var(--amber-15)' : 'rgba(255,255,255,0.04)', border: `0.5px solid ${isDeterministic ? 'var(--amber-40)' : 'rgba(255,255,255,0.08)'}`, borderRadius: '2px', padding: '2px 6px', letterSpacing: '0.08em', flexShrink: 0 }}>
                      {isDeterministic ? 'DETERMINISTIC' : 'LLM NARRATOR'}
                    </span>
                  </div>
                  {log.meta?.signals?.length > 0 && (
                    <div>
                      <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.15em', color: 'var(--text-muted)', marginBottom: '6px' }}>DECISION SIGNALS</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                        {log.meta.signals.map((s, i) => (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '4px 8px', background: 'var(--bg-card)', borderRadius: '3px', border: '0.5px solid var(--border-bright)' }}>
                            <span className={`arb-badge arb-${s.severity?.toLowerCase()}`} style={{ fontSize: '7px', flexShrink: 0 }}>{s.severity}</span>
                            <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)', flexShrink: 0 }}>[{s.category}]</span>
                            <span style={{ fontSize: '11px', color: 'var(--text-secondary)', flex: 1 }}>{s.label}</span>
                            <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--border-bright)' }}>{s.rule}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )
            })()}

            <div style={{ padding:'0 20px 20px' }}>

              <div style={{ display:'flex', flexDirection:'column', gap:'0', marginBottom:'14px' }}>
                <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em', textTransform:'uppercase', marginBottom:'8px', paddingTop:'14px', borderTop:'0.5px solid var(--border)' }}>RECOMMENDED ACTIONS</div>
                {entry.triage.recommendations.map((rec, i) => {
                  const prov = entry.triage.recommendation_provenance?.[i]
                  const provColors = { enrichment_confirmed:'var(--amber)', behavioral_heuristic:'#6B7FD4', known_good_override:'#4CAF50', account_action:'#E57373', forensic:'#9E9E9E' }
                  const provLabels = { enrichment_confirmed:'CTI', behavioral_heuristic:'HEURISTIC', known_good_override:'KNOWN-GOOD', account_action:'ACCOUNT', forensic:'FORENSIC' }
                  return (
                    <div key={i} style={{ display:'flex', gap:'10px', padding:'6px 0', borderBottom: i < entry.triage.recommendations.length - 1 ? '0.5px solid var(--border)' : 'none' }}>
                      <span style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', color:'var(--amber)', minWidth:'16px', flexShrink:0, marginTop:'1px' }}>0{i+1}</span>
                      <div style={{ flex:1 }}>
                        <span style={{ fontSize:'12px', color:'var(--text-secondary)', lineHeight:'1.5' }}>{typeof rec === 'object' ? JSON.stringify(rec) : String(rec ?? '')}</span>
                        {prov && (
                          <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'7px', color: provColors[prov] ?? 'var(--text-muted)', letterSpacing:'0.12em', marginTop:'2px' }}>
                            ▲ {provLabels[prov] ?? prov}
                          </div>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>

              {entry.ips?.length > 0 && (
                <div style={{ marginBottom:'14px' }}>
                  <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em', textTransform:'uppercase', marginBottom:'6px' }}>THREAT ENRICHMENT</div>
                  {entry.ips.map(ip => {
                    const d = entry.enrichment?.[ip]
                    return (
                      <div key={ip} style={{ background:'var(--bg-card)', border:'0.5px solid var(--border-bright)', borderRadius:'5px', padding:'10px 12px', marginBottom:'6px' }}>
                        <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'13px', fontWeight:'500', color:'var(--red)', marginBottom:'6px' }}>{ip}</div>
                        <div style={{ display:'flex', gap:'16px', flexWrap:'wrap' }}>
                          {d?.abuseipdb && <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', color:'var(--text-muted)' }}>AbuseIPDB <span style={{ color: d.abuseipdb.score >= 80 ? 'var(--red)' : 'var(--text-secondary)' }}>{d.abuseipdb.score}/100</span></div>}
                          {d?.virustotal && <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', color:'var(--text-muted)' }}>VT <span style={{ color: d.virustotal.malicious > 0 ? 'var(--red)' : 'var(--text-secondary)' }}>{d.virustotal.malicious}/{d.virustotal.total}</span></div>}
                          {d?.otx && <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', color:'var(--text-muted)' }}>OTX <span style={{ color: d.otx.pulseCount > 0 ? 'var(--red)' : 'var(--text-secondary)' }}>{d.otx.pulseCount} pulses</span></div>}
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}

              <div>
                <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em', textTransform:'uppercase', marginBottom:'6px' }}>RAW ALERT</div>
                <div className="arb-audit-raw" style={{ background:'var(--bg-input)', border:'0.5px solid var(--border-bright)', borderRadius:'4px', padding:'10px 12px' }}>{entry.alertText}</div>
              </div>

            </div>
          </div>
        </div>

      </div>
    </div>
  )
}
