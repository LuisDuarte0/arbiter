'use client'
import { useState } from 'react'

function formatTime(ts) {
  const d = new Date(ts)
  return d.toLocaleTimeString('en-US', { hour12: false }) + ' · ' + d.toLocaleDateString('en-GB')
}

const TACTICS = [
  { id: 'initial-access',        label: 'Initial Access' },
  { id: 'execution',             label: 'Execution' },
  { id: 'persistence',           label: 'Persistence' },
  { id: 'privilege-escalation',  label: 'Priv. Escalation' },
  { id: 'defense-evasion',       label: 'Defense Evasion' },
  { id: 'credential-access',     label: 'Credential Access' },
  { id: 'discovery',             label: 'Discovery' },
  { id: 'lateral-movement',      label: 'Lateral Movement' },
  { id: 'collection',            label: 'Collection' },
  { id: 'exfiltration',          label: 'Exfiltration' },
  { id: 'impact',                label: 'Impact' },
]

function normalizeTactic(t) {
  if (!t) return 'unknown'
  return t.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z-]/g, '')
}

function buildHeatmap(logs) {
  const map = {}
  logs.forEach(log => {
    const id  = log.triage?.mitre_id
    const name = log.triage?.mitre_name
    const tac  = log.triage?.mitre_tactic ?? log.triage?.tactic
    if (!id) return
    if (!map[id]) map[id] = { id, name: name ?? id, tactic: normalizeTactic(tac), count: 0, cases: [] }
    map[id].count++
    map[id].cases.push(log.id)
  })
  return map
}

function cellBg(count) {
  if (count === 0) return { bg: 'rgba(255,255,255,0.02)', border: 'var(--border)', color: 'var(--text-muted)', textColor: 'var(--text-muted)' }
  if (count === 1) return { bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.3)', color: '#F59E0B', textColor: 'var(--text-secondary)' }
  if (count === 2) return { bg: 'rgba(245,158,11,0.25)', border: 'rgba(245,158,11,0.5)', color: '#F59E0B', textColor: '#D4A017' }
  return { bg: '#F59E0B', border: '#F59E0B', color: '#080C14', textColor: '#080C14' }
}

function MitreMatrix({ logs }) {
  const [selected, setSelected] = useState(null)

  if (!logs.length) return (
    <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'center', fontFamily:'var(--font-mono),monospace', fontSize:'10px', color:'var(--text-muted)', letterSpacing:'0.1em' }}>
      NO DETECTION DATA — RUN ANALYSES TO POPULATE
    </div>
  )

  const map      = buildHeatmap(logs)
  const byTactic = {}
  TACTICS.forEach(t => { byTactic[t.id] = [] })
  Object.values(map).forEach(tech => {
    const key = tech.tactic
    if (!byTactic[key]) byTactic[key] = []
    byTactic[key].push(tech)
  })

  const unique   = Object.keys(map).length
  const covered  = TACTICS.filter(t => byTactic[t.id]?.length > 0).length
  const gaps     = TACTICS.length - covered

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%' }}>

      {/* STATS */}
      <div style={{ padding:'10px 20px', borderBottom:'0.5px solid var(--border)', display:'flex', gap:'24px', flexShrink:0 }}>
        {[
          { label:'TECHNIQUES', value: unique, color:'var(--amber)' },
          { label:'ANALYSES',   value: logs.length, color:'var(--text-secondary)' },
          { label:'TACTICS',    value: `${covered}/11`, color:'var(--text-secondary)' },
          { label:'GAPS',       value: gaps, color: gaps > 0 ? 'var(--red)' : 'var(--green)' },
        ].map(s => (
          <div key={s.label}>
            <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em', marginBottom:'3px' }}>{s.label}</div>
            <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'18px', fontWeight:'600', color:s.color, lineHeight:1 }}>{s.value}</div>
          </div>
        ))}
        <div style={{ marginLeft:'auto', display:'flex', alignItems:'flex-end', gap:'10px', paddingBottom:'2px' }}>
          {[
            { bg:'rgba(245,158,11,0.12)', label:'1×' },
            { bg:'rgba(245,158,11,0.25)', label:'2×' },
            { bg:'#F59E0B',               label:'3×+' },
          ].map(l => (
            <div key={l.label} style={{ display:'flex', alignItems:'center', gap:'5px' }}>
              <div style={{ width:'18px', height:'8px', borderRadius:'2px', background:l.bg, border:'0.5px solid rgba(245,158,11,0.3)' }} />
              <span style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)' }}>{l.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* COMPACT MATRIX — all 11 tactics always visible */}
      <div style={{ flex:1, overflowY:'auto', padding:'14px 20px' }}>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(11, 1fr)', gap:'4px', minWidth:'700px' }}>
          {TACTICS.map(tactic => (
            <div key={tactic.id} style={{ display:'flex', flexDirection:'column', gap:'3px' }}>
              {/* Tactic header */}
              <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'7px', letterSpacing:'0.1em', color: byTactic[tactic.id]?.length ? 'var(--amber)' : 'var(--text-muted)', textTransform:'uppercase', padding:'4px 4px 5px', borderBottom:'0.5px solid var(--border)', textAlign:'center', lineHeight:'1.3' }}>
                {tactic.label}
              </div>

              {/* Detected techniques */}
              {byTactic[tactic.id]?.sort((a,b) => b.count - a.count).map(tech => {
                const c = cellBg(tech.count)
                const isSel = selected === tech.id
                return (
                  <div
                    key={tech.id}
                    onClick={() => setSelected(isSel ? null : tech.id)}
                    style={{ background:c.bg, border:`0.5px solid ${isSel ? 'var(--amber)' : c.border}`, borderRadius:'3px', padding:'4px 5px', cursor:'pointer', transition:'opacity 0.15s' }}
                    title={`${tech.id} · ${tech.name} · ${tech.count} detection${tech.count !== 1 ? 's' : ''}`}
                  >
                    <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'7.5px', color:c.color, fontWeight:'600', marginBottom:'1px' }}>{tech.id}</div>
                    <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'7px', color:c.textColor, lineHeight:'1.3', overflow:'hidden', display:'-webkit-box', WebkitLineClamp:2, WebkitBoxOrient:'vertical' }}>{tech.name}</div>
                    {isSel && (
                      <div style={{ marginTop:'4px', paddingTop:'4px', borderTop:`0.5px solid ${c.border}` }}>
                        <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'7px', color:c.textColor, opacity:0.8 }}>{tech.count}× detected</div>
                        {tech.cases.slice(0,2).map((cid,i) => (
                          <div key={i} style={{ fontFamily:'var(--font-mono),monospace', fontSize:'7px', color:c.textColor, opacity:0.6, marginTop:'1px' }}>{cid.slice(4,14)}</div>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}

              {/* Gap cell */}
              {!byTactic[tactic.id]?.length && (
                <div style={{ background:'rgba(239,68,68,0.04)', border:'0.5px solid rgba(239,68,68,0.12)', borderRadius:'3px', padding:'4px 5px' }}>
                  <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'7px', color:'rgba(239,68,68,0.35)', textAlign:'center' }}>—</div>
                </div>
              )}
            </div>
          ))}
        </div>
        <div style={{ marginTop:'10px', fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', textAlign:'right' }}>
          CLICK TECHNIQUE TO EXPAND · HOVER FOR DETAILS
        </div>
      </div>
    </div>
  )
}

export default function AuditLog({ onClose }) {
  const [selected,  setSelected]  = useState(0)
  const [activeTab, setActiveTab] = useState('log')

  const logs = (() => {
    try { return JSON.parse(localStorage.getItem('arbiter_audit') ?? '[]') }
    catch { return [] }
  })()

  const tabBtn = (id, label, badge) => (
    <button
      style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', letterSpacing:'0.12em', padding:'9px 16px', cursor:'pointer', border:'none', background:'none', color: activeTab === id ? 'var(--amber)' : 'var(--text-muted)', borderBottom: activeTab === id ? '2px solid var(--amber)' : '2px solid transparent' }}
      onClick={() => setActiveTab(id)}
    >
      {label}
      {badge != null && <span style={{ marginLeft:'5px', color:'var(--amber)', fontSize:'9px' }}>({badge})</span>}
    </button>
  )

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

  function clearAll() {
    if (!confirm('Clear all audit logs? This cannot be undone.')) return
    localStorage.removeItem('arbiter_audit')
    localStorage.removeItem('arbiter_history')
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
  const uniqueTechs = [...new Set(logs.map(l => l.triage?.mitre_id).filter(Boolean))].length

  return (
    <div className="arb-modal-overlay" onClick={onClose}>
      <div className="arb-modal" onClick={e => e.stopPropagation()}>

        {/* HEADER */}
        <div className="arb-modal-header">
          <div style={{ display:'flex', alignItems:'center', gap:'10px' }}>
            <span className="arb-panel-title">AUDIT LOG</span>
            <span className="arb-panel-badge">{logs.length} {logs.length === 1 ? 'ENTRY' : 'ENTRIES'}</span>
          </div>
          <div style={{ display:'flex', gap:'6px', alignItems:'center' }}>
            {activeTab === 'log' && (
              <>
                <button className="arb-audit-action-btn" onClick={exportOne}>EXPORT SELECTED</button>
                <button className="arb-audit-action-btn" onClick={exportAll}>EXPORT ALL</button>
                <button
                  className="arb-audit-action-btn"
                  onClick={clearAll}
                  style={{ color:'var(--red)', borderColor:'var(--red-40)' }}
                  onMouseEnter={e => { e.currentTarget.style.background = 'var(--red-15)' }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'none' }}
                >
                  CLEAR ALL
                </button>
              </>
            )}
            <button className="arb-audit-close" onClick={onClose}>✕</button>
          </div>
        </div>

        {/* TABS */}
        <div style={{ display:'flex', borderBottom:'0.5px solid var(--border)', flexShrink:0 }}>
          {tabBtn('log',     'TRIAGE LOG')}
          {tabBtn('heatmap', 'MITRE COVERAGE', uniqueTechs)}
        </div>

        {/* MITRE TAB */}
        {activeTab === 'heatmap' && (
          <div style={{ flex:1, overflow:'hidden', display:'flex', flexDirection:'column' }}>
            <MitreMatrix logs={logs} />
          </div>
        )}

        {/* LOG TAB */}
        {activeTab === 'log' && (
          <div className="arb-modal-body">

            {/* LEFT LIST */}
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

            {/* RIGHT DETAIL */}
            <div className="arb-modal-detail">
              <div style={{ padding:'16px 20px', display:'flex', flexDirection:'column', gap:'14px' }}>

                {/* CASE HEADER */}
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

                {/* TWO COL — MITRE + ASSET */}
                <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'10px' }}>
                  <div style={{ background:'var(--bg-card)', border:'0.5px solid var(--border-bright)', borderRadius:'5px', padding:'10px 12px' }}>
                    <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em', marginBottom:'6px' }}>MITRE ATT&CK</div>
                    <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'11px', color:'var(--amber)', fontWeight:'500', marginBottom:'3px' }}>{entry.triage.mitre_id}</div>
                    <div style={{ fontSize:'12px', fontWeight:'500', color:'var(--text-primary)' }}>{entry.triage.mitre_name}</div>
                  </div>
                  <div style={{ background:'var(--bg-card)', border:'0.5px solid var(--border-bright)', borderRadius:'5px', padding:'10px 12px' }}>
                    <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em', marginBottom:'6px' }}>AFFECTED ASSET</div>
                    <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'13px', fontWeight:'500', color:'var(--text-primary)', marginBottom:'4px' }}>{entry.triage.affected_asset}</div>
                    {entry.triage.asset_is_critical && <span className="arb-asset-critical">CRITICAL ASSET</span>}
                  </div>
                </div>

                {/* REASONING */}
                <div>
                  <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em', textTransform:'uppercase', marginBottom:'6px' }}>ARBITER REASONING</div>
                  <div style={{ background:'var(--bg-input)', borderLeft:'2px solid var(--amber)', borderRadius:'0 4px 4px 0', padding:'10px 14px', fontSize:'12px', color:'var(--text-secondary)', lineHeight:'1.75' }}>{entry.triage.reasoning}</div>
                </div>

                {/* RECOMMENDATIONS */}
                <div>
                  <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em', textTransform:'uppercase', marginBottom:'8px' }}>RECOMMENDED ACTIONS</div>
                  <div style={{ display:'flex', flexDirection:'column', gap:'0' }}>
                    {entry.triage.recommendations.map((rec, i) => (
                      <div key={i} style={{ display:'flex', gap:'10px', padding:'6px 0', borderBottom: i < entry.triage.recommendations.length - 1 ? '0.5px solid var(--border)' : 'none' }}>
                        <span style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', color:'var(--amber)', minWidth:'16px', flexShrink:0, marginTop:'1px' }}>0{i+1}</span>
                        <span style={{ fontSize:'12px', color:'var(--text-secondary)', lineHeight:'1.5' }}>{rec}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* ENRICHMENT */}
                {entry.ips?.length > 0 && (
                  <div>
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

                {/* RAW ALERT */}
                <div>
                  <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em', textTransform:'uppercase', marginBottom:'6px' }}>RAW ALERT</div>
                  <div className="arb-audit-raw" style={{ background:'var(--bg-input)', border:'0.5px solid var(--border-bright)', borderRadius:'4px', padding:'10px 12px' }}>{entry.alertText}</div>
                </div>

              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  )
}