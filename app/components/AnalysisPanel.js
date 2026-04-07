// Layout styles here specifically are inline due to Turbopack CSS caching during dev. refactor candidate

'use client'

function Badge({ severity }) {
  return <span className={`arb-badge arb-${severity.toLowerCase()}`}>{severity}</span>
}

const S = {
  verdictHero: {
    padding: '20px 22px 16px',
    borderBottom: '0.5px solid var(--border)',
  },
  verdictTop: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    marginBottom: '12px',
  },
  verdictTitle: {
    fontSize: '26px',
    fontWeight: '500',
    color: 'var(--text-primary)',
    lineHeight: '1.1',
    marginBottom: '6px',
    letterSpacing: '-0.01em',
  },
  verdictSub: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '11px',
    color: 'var(--text-secondary)',
  },
  verdictRight: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-end',
    gap: '4px',
  },
  confBig: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '32px',
    fontWeight: '600',
    color: 'var(--amber)',
    lineHeight: '1',
  },
  confUnit: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '12px',
    color: 'var(--text-muted)',
  },
  confLabel: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '9px',
    color: 'var(--text-muted)',
    letterSpacing: '0.1em',
  },
  verdictBarWrap: {
    height: '2px',
    background: 'var(--border-bright)',
    borderRadius: '1px',
    overflow: 'hidden',
    width: '80px',
    marginTop: '4px',
  },
  metaGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '10px',
    padding: '14px 22px',
    borderBottom: '0.5px solid var(--border)',
  },
  metaBlock: {
    background: 'var(--bg-card)',
    border: '0.5px solid var(--border-bright)',
    borderRadius: '6px',
    padding: '12px 14px',
  },
  metaLabel: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '9px',
    letterSpacing: '0.15em',
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    marginBottom: '7px',
  },
  metaId: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '12px',
    color: 'var(--amber)',
    fontWeight: '500',
    marginBottom: '3px',
  },
  metaName: {
    fontSize: '13px',
    fontWeight: '500',
    color: 'var(--text-primary)',
    marginBottom: '3px',
  },
  metaDetail: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '10px',
    color: 'var(--text-secondary)',
  },
  assetNameLg: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '15px',
    fontWeight: '500',
    color: 'var(--text-primary)',
    marginBottom: '4px',
  },
  evidenceSection: {
    padding: '12px 22px',
    borderBottom: '0.5px solid var(--border)',
  },
  evidenceChips: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '6px',
    marginTop: '8px',
  },
  chip: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '10px',
    background: 'var(--amber-15)',
    color: 'var(--amber)',
    border: '0.5px solid var(--amber-40)',
    borderRadius: '3px',
    padding: '4px 10px',
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
  },
  chipSep: { color: 'rgba(245,158,11,0.4)' },
  chipVal: { color: 'var(--text-primary)' },
  stepsSection: {
    padding: '14px 22px',
    borderBottom: '0.5px solid var(--border)',
  },
  stepsList: {
    marginTop: '10px',
    display: 'flex',
    flexDirection: 'column',
  },
  step: {
    display: 'flex',
    gap: '14px',
  },
  stepLeft: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    width: '22px',
    flexShrink: '0',
  },
  stepNum: {
    width: '22px',
    height: '22px',
    borderRadius: '50%',
    background: 'var(--bg-card)',
    border: '0.5px solid var(--amber-40)',
    color: 'var(--amber)',
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '9px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: '0',
  },
  stepLine: {
    width: '0.5px',
    flex: '1',
    background: 'var(--border-bright)',
    minHeight: '10px',
    margin: '3px 0',
  },
  reasoningSection: {
    padding: '14px 22px 20px',
  },
  reasoningLabel: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '9px',
    letterSpacing: '0.15em',
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    marginBottom: '10px',
  },
  reasoningBody: {
    background: 'var(--bg-input)',
    borderLeft: '2px solid var(--amber)',
    borderRadius: '0 5px 5px 0',
    padding: '14px 18px',
    fontSize: '13px',
    color: 'var(--text-secondary)',
    lineHeight: '1.85',
  },
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
        <div>

          <div style={S.verdictHero}>
            <div style={S.verdictTop}>
              <div>
                <div style={{ marginBottom: '8px' }}>
                  <Badge severity={triage.severity} />
                </div>
                <div style={S.verdictTitle}>{triage.classification}</div>
                <div style={S.verdictSub}>{triage.tactic} · {triage.mitre_id}</div>
              </div>
              <div style={S.verdictRight}>
                <div>
                  <span style={S.confBig}>{triage.confidence}</span>
                  <span style={S.confUnit}>%</span>
                </div>
                <div style={S.confLabel}>CONFIDENCE</div>
                <div style={S.verdictBarWrap}>
                  <div style={{ height: '100%', background: 'var(--amber)', borderRadius: '1px', width: `${triage.confidence}%`, transition: 'width 0.6s ease' }} />
                </div>
              </div>
            </div>
          </div>

          <div style={S.metaGrid}>
            <div style={S.metaBlock}>
              <div style={S.metaLabel}>MITRE ATT&CK</div>
              <div style={S.metaId}>{triage.mitre_id}</div>
              <div style={S.metaName}>{triage.mitre_name}</div>
              <div style={S.metaDetail}>{triage.mitre_tactic} · Windows</div>
            </div>
            <div style={S.metaBlock}>
              <div style={S.metaLabel}>Affected Asset</div>
              <div style={S.assetNameLg}>{triage.affected_asset}</div>
              {triage.asset_is_critical && (
                <span className="arb-asset-critical">CRITICAL ASSET</span>
              )}
            </div>
          </div>

          {triage.evidence?.length > 0 && (
            <div style={S.evidenceSection}>
              <div style={S.metaLabel}>EVIDENCE — WHY THIS VERDICT</div>
              <div style={S.evidenceChips}>
                {triage.evidence.map((item, i) => {
                  const eqIdx = item.indexOf('=')
                  const field = eqIdx > -1 ? item.slice(0, eqIdx) : item
                  const val = eqIdx > -1 ? item.slice(eqIdx + 1) : ''
                  return (
                    <div key={i} style={S.chip}>
                      <span>{field}</span>
                      {val && (
                        <>
                          <span style={S.chipSep}>=</span>
                          <span style={S.chipVal}>{val}</span>
                        </>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          <div style={S.stepsSection}>
            <div style={S.metaLabel}>RECOMMENDED ACTIONS</div>
            <div style={S.stepsList}>
              {triage.recommendations.map((rec, i) => (
                <div key={i} style={S.step}>
                  <div style={S.stepLeft}>
                    <div style={S.stepNum}>{String(i + 1).padStart(2, '0')}</div>
                    {i < triage.recommendations.length - 1 && (
                      <div style={S.stepLine} />
                    )}
                  </div>
                  <div style={{ padding: i === triage.recommendations.length - 1 ? '2px 0 0' : '2px 0 14px', flex: '1' }}>
                    <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: '1.55' }}>{rec}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={S.reasoningSection}>
            <div style={S.reasoningLabel}>ARBITER REASONING</div>
            <div style={S.reasoningBody}>{triage.reasoning}</div>
          </div>

        </div>
      )}
    </div>
  )
}