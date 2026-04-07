'use client'

function Badge({ severity }) {
  return <span className={`arb-badge arb-${severity.toLowerCase()}`}>{severity}</span>
}

export default function AnalysisPanel({ alertText, setAlertText, result, loading, error, onTriage, onReset }) {
  const triage = result?.triage ?? null

  return (
    <div className="arb-panel arb-analysis">
      <div className="arb-panel-header">
        <span className="arb-panel-title">Analysis</span>
        <div className="arb-header-right">
          {triage && <Badge severity={triage.severity} />}
          {triage && <span className="arb-panel-badge">{triage.confidence}% CONFIDENCE</span>}
          {result && (
            <button
              onClick={onReset}
              style={{
                background: 'none',
                border: '0.5px solid var(--border-bright)',
                borderRadius: '3px',
                color: 'var(--text-muted)',
                fontFamily: 'var(--font-mono), monospace',
                fontSize: '10px',
                letterSpacing: '0.1em',
                cursor: 'pointer',
                padding: '3px 10px',
                transition: 'color 0.15s'
              }}
            >
              NEW ANALYSIS
            </button>
          )}
        </div>
      </div>

      <div className="arb-input-block">
        <div className="arb-input-header">
          <span className="arb-input-label">RAW ALERT INPUT</span>
          <span className="arb-input-hint">Paste any SIEM alert, Windows event, or log snippet</span>
        </div>
        <textarea
          className="arb-textarea"
          value={alertText}
          onChange={e => setAlertText(e.target.value)}
          placeholder={`EventCode=4625 LogonType=3\nTargetUserName=admin\nIpAddress=185.220.101.47\nFailureReason=%%2313\n\n— paste your alert here —`}
          spellCheck={false}
        />
        <button className="arb-button" onClick={onTriage} disabled={loading || !alertText.trim()}>
          {loading ? 'ANALYZING...' : 'ANALYZE ALERT →'}
        </button>
        {error && <div className="arb-error">{error}</div>}
      </div>

      {loading && (
        <div className="arb-loading">
          <div className="arb-loading-dot" />
          <span className="arb-loading-text">ARBITER IS ANALYZING YOUR ALERT</span>
        </div>
      )}

      {triage && (
        <div className="arb-output">
          <div className="arb-triage-top">
            <div>
              <div className="arb-card-label">CLASSIFICATION</div>
              <div className="arb-cls-value">{triage.classification}</div>
              <div className="arb-cls-sub">{triage.tactic} — {triage.mitre_name}</div>
            </div>
            <div className="arb-triage-right">
              <Badge severity={triage.severity} />
              <div>
                <div className="arb-conf-label">CONFIDENCE</div>
                <div className="arb-conf-value">{triage.confidence}%</div>
                <div className="arb-conf-bar">
                  <div className="arb-conf-fill" style={{ width: `${triage.confidence}%` }} />
                </div>
              </div>
            </div>
          </div>

          <div className="arb-card">
            <div className="arb-card-label">MITRE ATT&CK</div>
            <div className="arb-mitre-id">{triage.mitre_id}</div>
            <div className="arb-mitre-name">{triage.mitre_name}</div>
            <div className="arb-mitre-meta">Tactic: {triage.mitre_tactic} · Platform: Windows · Data Source: Security Logs</div>
          </div>

          <div className="arb-card">
            <div className="arb-card-label">AFFECTED ASSET</div>
            <div className="arb-asset-row">
              <span className="arb-asset-name">{triage.affected_asset}</span>
              {triage.asset_is_critical && <span className="arb-asset-critical">CRITICAL ASSET</span>}
            </div>
          </div>

          <div className="arb-card">
            <div className="arb-card-label">RECOMMENDED ACTIONS</div>
            <div className="arb-rec-list">
              {triage.recommendations.map((rec, i) => (
                <div key={i} className="arb-rec-item">
                  <span className="arb-rec-num">0{i + 1}</span>
                  <span className="arb-rec-text">{rec}</span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div className="arb-card-label" style={{ marginBottom: '10px' }}>ARBITER REASONING</div>
            <div className="arb-reasoning">{triage.reasoning}</div>
          </div>
        </div>
      )}
    </div>
  )
}