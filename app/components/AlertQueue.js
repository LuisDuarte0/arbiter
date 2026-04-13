'use client'
import { useState } from 'react'

function timeAgo(date) {
  const s = Math.floor((new Date() - date) / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  return `${Math.floor(m / 60)}h ago`
}

export default function AlertQueue({ history, activeId, collapsed, onToggle, onSelect, mitreFilter, onMitreFilter, ipFilter, onIpFilter }) {
  const [query, setQuery] = useState('')

  const filtered = (() => {
    let items = history
    if (ipFilter) {
      items = items.filter(item =>
        item.fullResult?.ips?.includes(ipFilter) ||
        item.fullResult?.triage?.affected_asset?.includes(ipFilter)
      )
    }
    if (mitreFilter) {
      items = items.filter(item => item.fullResult?.triage?.mitre_id?.startsWith(mitreFilter))
    }
    if (query.trim()) {
      const q = query.toLowerCase()
      items = items.filter(item =>
        item.classification?.toLowerCase().includes(q) ||
        item.asset?.toLowerCase().includes(q) ||
        item.tactic?.toLowerCase().includes(q) ||
        item.severity?.toLowerCase().includes(q) ||
        item.id?.toLowerCase().includes(q)
      )
    }
    return items
  })()

  return (
    <div className={`arb-panel arb-queue${collapsed ? ' arb-panel-collapsed' : ''}`}>
      <div className="arb-panel-header">
        {!collapsed && <span className="arb-panel-title">History</span>}
        <div style={{ display:'flex', gap:'8px', alignItems:'center', marginLeft: collapsed ? 'auto' : undefined }}>
          {!collapsed && <span className="arb-panel-badge">{history.length}</span>}
          <button className="arb-collapse-btn" onClick={onToggle} title={collapsed ? 'Expand' : 'Collapse'}>
            {collapsed ? '›' : '‹'}
          </button>
        </div>
      </div>

      <div className="arb-panel-content">

        {mitreFilter && (
          <div style={{
            padding: '5px 12px',
            borderBottom: '0.5px solid var(--border)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: 'var(--amber-15)',
            flexShrink: 0,
          }}>
            <span style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '9px', color: 'var(--amber)', letterSpacing: '0.08em' }}>
              FILTER: {mitreFilter}
            </span>
            <span
              onClick={() => onMitreFilter?.(null)}
              style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '9px', color: 'var(--text-muted)', cursor: 'pointer', letterSpacing: '0.08em' }}
            >
              ✕ CLEAR
            </span>
          </div>
        )}

        {ipFilter && (
          <div style={{ padding: '5px 12px', borderBottom: '0.5px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(229,115,115,0.08)', flexShrink: 0 }}>
            <span style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '9px', color: '#E57373', letterSpacing: '0.08em' }}>IP: {ipFilter}</span>
            <span onClick={() => onIpFilter?.(null)} style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '9px', color: 'var(--text-muted)', cursor: 'pointer', letterSpacing: '0.08em' }}>✕ CLEAR</span>
          </div>
        )}

        {history.length > 0 && (
          <div style={{ padding:'8px 12px', borderBottom:'0.5px solid var(--border)', flexShrink:0 }}>
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search history..."
              style={{
                width:'100%',
                background:'var(--bg-input)',
                border:'0.5px solid var(--border-bright)',
                borderRadius:'3px',
                padding:'5px 8px',
                fontFamily:'var(--font-mono),monospace',
                fontSize:'10px',
                color:'var(--text-secondary)',
                outline:'none',
              }}
            />
          </div>
        )}

        {activeId && !query && !mitreFilter && (
          <div className="arb-queue-item arb-queue-active">
            <div className="arb-queue-top">
              <span className="arb-queue-id">{activeId.slice(4, 17)}</span>
              <span className="arb-badge arb-high">ANALYZING</span>
            </div>
            <div className="arb-queue-tactic">In progress...</div>
            <div className="arb-queue-asset">RUNNING · {new Date().toISOString().slice(11,19)}Z</div>
          </div>
        )}

        {history.length === 0 && !activeId && (
          <div className="arb-queue-empty" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px', padding: '32px 16px' }}>
            <svg viewBox="-8 0 136 120" width="32" height="28" xmlns="http://www.w3.org/2000/svg">
              <line x1="60" y1="8" x2="6" y2="112" stroke="rgba(255,255,255,0.15)" strokeWidth="17" strokeLinecap="square"/>
              <line x1="60" y1="8" x2="114" y2="112" stroke="rgba(255,255,255,0.15)" strokeWidth="17" strokeLinecap="square"/>
              <line x1="-6" y1="68" x2="126" y2="68" stroke="rgba(255,255,255,0.15)" strokeWidth="7" strokeLinecap="square"/>
            </svg>
            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'rgba(255,255,255,0.35)', letterSpacing: '0.15em', textAlign: 'center', lineHeight: '2.0', textTransform: 'uppercase' }}>
              NO ACTIVE CASES
              <span style={{ display: 'block', fontSize: '9px', opacity: 0.55, letterSpacing: '0.08em', textTransform: 'none', marginTop: '4px' }}>
                Submit an alert to begin triage.
              </span>
            </div>
          </div>
        )}

        {(query || mitreFilter) && filtered.length === 0 && (
          <div className="arb-queue-empty">
            {mitreFilter ? `No results for ${mitreFilter}` : `No results for "${query}"`}
          </div>
        )}

        {filtered.map(item => (
          <div
            key={item.id}
            className="arb-queue-item"
            onClick={() => onSelect?.(item)}
          >
            <div className="arb-queue-top">
              <span className="arb-queue-id">{item.id.slice(4, 17)}</span>
              <span className={`arb-badge arb-${item.severity.toLowerCase()}`}>{item.severity}</span>
            </div>
            <div className="arb-queue-tactic">{item.classification}</div>
            <div className="arb-queue-asset">{item.asset} · {timeAgo(item.timestamp)}</div>
          </div>
        ))}

        {history.length > 0 && (
          <div className="arb-queue-footer">
            {mitreFilter
              ? `${filtered.length} of ${history.length} · ${mitreFilter}`
              : query
              ? `${filtered.length} of ${history.length} shown`
              : `${history.length} ${history.length === 1 ? 'analysis' : 'analyses'} this session`
            }
          </div>
        )}

      </div>
    </div>
  )
}