'use client'
import { useState } from 'react'

function formatTime(ts) {
  const d = new Date(ts)
  return d.toLocaleTimeString('en-US', { hour12: false }) + ' · ' + d.toLocaleDateString('en-GB')
}

export default function AuditLog({ onClose }) {
  const [selected, setSelected] = useState(0)

  const logs = (() => {
    try { return JSON.parse(localStorage.getItem('arbiter_audit') ?? '[]') }
    catch { return [] }
  })()

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

  function exportAll() {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `arbiter-audit-${Date.now()}.json`
    a.click()
  }

  function exportOne() {
    const blob = new Blob([JSON.stringify(entry, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `arbiter-${entry.id}.json`
    a.click()
  }

  function clearAll() {
    if (!confirm('Clear all audit logs? This cannot be undone.')) return
    localStorage.removeItem('arbiter_audit')
    onClose()
  }

  return (
    <div className="arb-modal-overlay" onClick={onClose}>
      <div className="arb-modal" onClick={e => e.stopPropagation()}>
        <div className="arb-modal-header">
          <div style={{ display:'flex', alignItems:'center', gap:'12px' }}>
            <span className="arb-panel-title">AUDIT LOG</span>
            <span className="arb-panel-badge">{logs.length} {logs.length === 1 ? 'ENTRY' : 'ENTRIES'}</span>
          </div>
          <div style={{ display:'flex', gap:'8px', alignItems:'center' }}>
            <button className="arb-audit-action-btn" onClick={exportOne}>EXPORT SELECTED</button>
            <button className="arb-audit-action-btn" onClick={exportAll}>EXPORT ALL</button>
            <button className="arb-audit-action-btn arb-audit-danger" onClick={clearAll}>CLEAR</button>
            <button className="arb-audit-close" onClick={onClose}>✕</button>
          </div>
        </div>

        <div className="arb-modal-body">
          <div className="arb-modal-list">
            {logs.map((log, i) => (
              <div
                key={log.id}
                className={`arb-modal-item${i === selected ? ' arb-modal-item-active' : ''}`}
                onClick={() => setSelected(i)}
              >
                <div className="arb-queue-top">
                  <span className="arb-queue-id">{log.id.slice(4, 17)}</span>
                  <span className={`arb-badge arb-${log.triage.severity.toLowerCase()}`}>{log.triage.severity}</span>
                </div>
                <div className="arb-queue-tactic">{log.triage.classification}</div>
                <div className="arb-queue-asset">{log.triage.affected_asset}</div>
                <div className="arb-queue-asset" style={{ marginTop:'2px' }}>{formatTime(log.timestamp)}</div>
              </div>
            ))}
          </div>

          <div className="arb-modal-detail">
            <div style={{ padding:'20px', display:'flex', flexDirection:'column', gap:'16px' }}>

              <div>
                <div className="arb-card-label">CASE</div>
                <div style={{ display:'flex', gap:'10px', alignItems:'center', flexWrap:'wrap' }}>
                  <span className="arb-queue-id" style={{ fontSize:'11px' }}>{entry.id}</span>
                  <span className={`arb-badge arb-${entry.triage.severity.toLowerCase()}`}>{entry.triage.severity}</span>
                  <span className="arb-panel-badge">{entry.triage.confidence}% CONFIDENCE</span>
                  <span className="arb-queue-asset">{formatTime(entry.timestamp)}</span>
                </div>
              </div>

              <div className="arb-card">
                <div className="arb-card-label">CLASSIFICATION</div>
                <div className="arb-cls-value" style={{ fontSize:'16px' }}>{entry.triage.classification}</div>
                <div className="arb-cls-sub">{entry.triage.tactic} — {entry.triage.mitre_name}</div>
                <div style={{ marginTop:'8px' }}>
                  <span className="arb-mitre-id">{entry.triage.mitre_id}</span>
                </div>
              </div>

              <div className="arb-card">
                <div className="arb-card-label">ARBITER REASONING</div>
                <div className="arb-reasoning">{entry.triage.reasoning}</div>
              </div>

              <div className="arb-card">
                <div className="arb-card-label">RECOMMENDED ACTIONS</div>
                <div className="arb-rec-list" style={{ marginTop:'4px' }}>
                  {entry.triage.recommendations.map((rec, i) => (
                    <div key={i} className="arb-rec-item">
                      <span className="arb-rec-num">0{i+1}</span>
                      <span className="arb-rec-text">{rec}</span>
                    </div>
                  ))}
                </div>
              </div>

              {entry.ips?.length > 0 && (
                <div className="arb-card">
                  <div className="arb-card-label">THREAT ENRICHMENT</div>
                  {entry.ips.map(ip => {
                    const d = entry.enrichment?.[ip]
                    return (
                      <div key={ip} style={{ marginBottom:'10px' }}>
                        <div className="arb-ip-address" style={{ fontSize:'14px', marginBottom:'6px' }}>{ip}</div>
                        {d?.abuseipdb && (
                          <div className="arb-audit-meta-item" style={{ color:'var(--text-muted)' }}>
                            AbuseIPDB: <span style={{ color: d.abuseipdb.score >= 80 ? 'var(--red)' : 'var(--text-secondary)' }}>{d.abuseipdb.score}/100</span> · {d.abuseipdb.isp}
                          </div>
                        )}
                        {d?.virustotal && (
                          <div className="arb-audit-meta-item" style={{ color:'var(--text-muted)' }}>
                            VirusTotal: <span style={{ color: d.virustotal.malicious > 0 ? 'var(--red)' : 'var(--text-secondary)' }}>{d.virustotal.malicious}/{d.virustotal.total} engines</span>
                          </div>
                        )}
                        {d?.otx && (
                          <div className="arb-audit-meta-item" style={{ color:'var(--text-muted)' }}>
                            OTX: <span style={{ color: d.otx.pulseCount > 0 ? 'var(--red)' : 'var(--text-secondary)' }}>{d.otx.pulseCount} pulses</span>
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}

              <div className="arb-card">
                <div className="arb-card-label">RAW ALERT</div>
                <div className="arb-audit-raw" style={{ marginTop:'8px' }}>{entry.alertText}</div>
              </div>

            </div>
          </div>
        </div>
      </div>
    </div>
  )
}