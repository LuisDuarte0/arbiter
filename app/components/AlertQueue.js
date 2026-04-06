'use client'

function timeAgo(date) {
  const s = Math.floor((new Date() - date) / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  return `${Math.floor(m / 60)}h ago`
}

export default function AlertQueue({ history, activeId, collapsed, onToggle }) {
  if (collapsed) {
    return (
      <div className="arb-queue-collapsed">
        <button className="arb-collapse-btn" onClick={onToggle} title="Expand history">›</button>
      </div>
    )
  }

  return (
    <div className="arb-panel arb-queue">
      <div className="arb-panel-header">
        <span className="arb-panel-title">History</span>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className="arb-panel-badge">{history.length}</span>
          <button className="arb-collapse-btn" onClick={onToggle} title="Collapse">‹</button>
        </div>
      </div>

      {activeId && (
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
        <div className="arb-queue-empty">
          No analyses yet.<br />
          Paste an alert and hit<br />
          ANALYZE ALERT to begin.
        </div>
      )}

      {history.map((item) => (
        <div key={item.id} className="arb-queue-item">
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
          {history.length} {history.length === 1 ? 'analysis' : 'analyses'} this session
        </div>
      )}
    </div>
  )
}