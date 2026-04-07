'use client'
import { useState } from 'react'
import ContainmentModal from './ContainmentModal'

function Badge({ severity }) {
  return <span className={`arb-badge arb-${severity.toLowerCase()}`}>{severity}</span>
}

const S = {
  // VERDICT HERO
  verdictHero: {
    padding: '18px 22px',
    borderBottom: '0.5px solid var(--border)',
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: '20px',
  },
  verdictLeft: {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
    flex: '1',
  },
  verdictTitle: {
    fontSize: '24px',
    fontWeight: '500',
    color: 'var(--text-primary)',
    lineHeight: '1.1',
    letterSpacing: '-0.01em',
  },
  verdictSub: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '10px',
    color: 'var(--text-secondary)',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    flexWrap: 'wrap',
  },
  verdictRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '20px',
    flexShrink: 0,
  },
  confBlock: {
    textAlign: 'right',
  },
  confBig: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '36px',
    fontWeight: '600',
    color: 'var(--amber)',
    lineHeight: '1',
  },
  confUnit: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '13px',
    color: 'var(--text-muted)',
  },
  confLabel: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '8px',
    color: 'var(--text-muted)',
    letterSpacing: '0.12em',
    marginTop: '3px',
  },
  confBarWrap: {
    width: '72px',
    height: '2px',
    background: 'var(--border-bright)',
    borderRadius: '1px',
    overflow: 'hidden',
    marginTop: '4px',
    marginLeft: 'auto',
  },

  // TWO-COLUMN BODY
  twoCol: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    borderBottom: '0.5px solid var(--border)',
  },
  leftCol: {
    padding: '16px 18px',
    borderRight: '0.5px solid var(--border)',
    display: 'flex',
    flexDirection: 'column',
    gap: '14px',
  },
  rightCol: {
    padding: '16px 18px',
    display: 'flex',
    flexDirection: 'column',
  },

  // LEFT COLUMN BLOCKS
  metaBlock: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
  },
  sectionLabel: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '8px',
    letterSpacing: '0.18em',
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    marginBottom: '6px',
  },
  metaId: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '11px',
    color: 'var(--amber)',
    fontWeight: '500',
  },
  metaName: {
    fontSize: '13px',
    fontWeight: '500',
    color: 'var(--text-primary)',
    lineHeight: '1.3',
  },
  metaDetail: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '9px',
    color: 'var(--text-secondary)',
    marginTop: '2px',
  },
  assetName: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '14px',
    fontWeight: '500',
    color: 'var(--text-primary)',
  },
  divider: {
    height: '0.5px',
    background: 'var(--border)',
  },
  evidenceChips: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '5px',
  },
  chip: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '9px',
    background: 'var(--amber-15)',
    color: 'var(--amber)',
    border: '0.5px solid var(--amber-40)',
    borderRadius: '3px',
    padding: '3px 8px',
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  },
  chipSep: { color: 'rgba(245,158,11,0.35)' },
  chipVal: { color: 'var(--text-primary)', fontSize: '9px' },

  // RIGHT COLUMN — ACTIONS
  actionsLabel: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '8px',
    letterSpacing: '0.18em',
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    marginBottom: '10px',
  },
  stepsList: {
    display: 'flex',
    flexDirection: 'column',
    flex: '1',
  },
  step: {
    display: 'flex',
    gap: '10px',
    alignItems: 'flex-start',
  },
  stepNum: {
    width: '18px',
    height: '18px',
    borderRadius: '50%',
    background: 'var(--bg-card)',
    border: '0.5px solid var(--amber-40)',
    color: 'var(--amber)',
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '8px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: '0',
    marginTop: '1px',
  },
  stepLine: {
    position: 'absolute',
    left: '8px',
    top: '20px',
    width: '0.5px',
    bottom: '0',
    background: 'var(--border-bright)',
  },
  stepText: {
    fontSize: '12px',
    color: 'var(--text-secondary)',
    lineHeight: '1.5',
    paddingBottom: '10px',
    flex: '1',
  },

  // REASONING — FULL WIDTH
  reasoningSection: {
    padding: '14px 22px',
    borderBottom: '0.5px solid var(--border)',
  },
  reasoningBody: {
    background: 'var(--bg-input)',
    borderLeft: '2px solid var(--amber)',
    borderRadius: '0 4px 4px 0',
    padding: '12px 16px',
    fontSize: '12.5px',
    color: 'var(--text-secondary)',
    lineHeight: '1.85',
  },

  // CONTAINMENT CTA
  containmentSection: {
    padding: '14px 22px 18px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '16px',
  },
  containmentLeft: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
  },
  containmentBtn: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    background: 'var(--amber)',
    border: 'none',
    borderRadius: '4px',
    padding: '9px 18px',
    cursor: 'pointer',
    transition: 'opacity 0.15s',
    flexShrink: 0,
  },
  containmentBtnLabel: {
    fontFamily: 'var(--font-mono), monospace',
    fontSize: '10px',
    fontWeight: '500',
    color: '#080C14',
    letterSpacing: '0.08em',
    whiteSpace: 'nowrap',
  },
}

export default function AnalysisPanel({ alertText, setAlertText, result, loading, error, onTriage, onReset }) {
  const triage = result?.triage ?? null
  const [containmentOpen, setContainmentOpen] = useState(false)

  return (
    <div className="arb-panel arb-analysis">

      {/* INPUT BLOCK */}
      <div className="arb-input-block">
        <div className="arb-input-header">
          <span className="arb-input-label">RAW ALERT INPUT</span>
          <label
            style={{
              fontFamily: 'var(--font-mono), monospace',
              fontSize: '9px',
              color: 'var(--amber)',
              letterSpacing: '0.08em',
              cursor: 'pointer',
              borderBottom: '0.5px solid var(--amber-40)',
              paddingBottom: '1px',
            }}
          >
            UPLOAD FILE
            <input
              type="file"
              accept=".txt,.log,.csv,.json,.xml,.evtx"
              style={{ display: 'none' }}
              onChange={e => {
                const file = e.target.files?.[0]
                if (!file) return
                const reader = new FileReader()
                reader.onload = ev => setAlertText(ev.target?.result ?? '')
                reader.readAsText(file)
                e.target.value = ''
              }}
            />
          </label>
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
        {error && (
          <div className="arb-error" style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', gap:'12px' }}>
            <span>
              {error === 'RATE_LIMIT'
                ? 'API rate limit reached. Groq free tier resets every few minutes — wait and try again.'
                : error}
            </span>
            {error === 'RATE_LIMIT' && (
              <button
                onClick={onTriage}
                style={{ background:'none', border:'0.5px solid var(--red-40)', borderRadius:'3px', color:'var(--red)', fontFamily:'var(--font-mono),monospace', fontSize:'9px', letterSpacing:'0.08em', cursor:'pointer', padding:'3px 8px', whiteSpace:'nowrap', flexShrink:0 }}
              >
                RETRY
              </button>
            )}
          </div>
        )}
      </div>

      {/* LOADING */}
      {loading && (
        <div className="arb-loading">
          <div className="arb-loading-dot" />
          <span className="arb-loading-text">ARBITER IS ANALYZING YOUR ALERT</span>
        </div>
      )}

      {/* RESULTS */}
      {triage && (
        <div>

          {/* VERDICT HERO — full width */}
          <div style={S.verdictHero}>
            <div style={S.verdictLeft}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Badge severity={triage.severity} />
              </div>
              <div style={S.verdictTitle}>{triage.classification}</div>
              <div style={S.verdictSub}>
                <span>{triage.tactic}</span>
                <span style={{ color: 'var(--border-bright)' }}>·</span>
                <span style={{ color: 'var(--amber)' }}>{triage.mitre_id}</span>
                {result?.meta?.processingTime && (
                  <>
                    <span style={{ color: 'var(--border-bright)' }}>·</span>
                    <span style={{ color: 'var(--text-muted)' }}>{(result.meta.processingTime / 1000).toFixed(1)}s</span>
                  </>
                )}
              </div>
            </div>
            <div style={S.verdictRight}>
              <div style={S.confBlock}>
                <div>
                  <span style={S.confBig}>{triage.confidence}</span>
                  <span style={S.confUnit}>%</span>
                </div>
                <div style={S.confLabel}>CONFIDENCE</div>
                <div style={S.confBarWrap}>
                  <div style={{ height: '100%', background: 'var(--amber)', borderRadius: '1px', width: `${triage.confidence}%` }} />
                </div>
              </div>
            </div>
          </div>

          {/* TWO COLUMN BODY */}
          <div style={S.twoCol}>

            {/* LEFT — MITRE + ASSET + EVIDENCE */}
            <div style={S.leftCol}>

              <div style={S.metaBlock}>
                <div style={S.sectionLabel}>MITRE ATT&CK</div>
                <div style={S.metaId}>{triage.mitre_id}</div>
                <div style={S.metaName}>{triage.mitre_name}</div>
                <div style={S.metaDetail}>{triage.mitre_tactic} · Windows · Security Logs</div>
              </div>

              <div style={S.divider} />

              <div style={S.metaBlock}>
                <div style={S.sectionLabel}>AFFECTED ASSET</div>
                <div style={S.assetName}>{triage.affected_asset}</div>
                {triage.asset_is_critical && (
                  <span className="arb-asset-critical" style={{ marginTop: '4px', display: 'inline-block' }}>CRITICAL ASSET</span>
                )}
              </div>

              {triage.evidence?.length > 0 && (
                <>
                  <div style={S.divider} />
                  <div>
                    <div style={S.sectionLabel}>EVIDENCE</div>
                    <div style={S.evidenceChips}>
                      {triage.evidence.map((item, i) => {
                        const eqIdx = item.indexOf('=')
                        const field = eqIdx > -1 ? item.slice(0, eqIdx) : item
                        const val   = eqIdx > -1 ? item.slice(eqIdx + 1) : ''
                        return (
                          <div key={i} style={S.chip}>
                            <span>{field}</span>
                            {val && (
                              <>
                                <span style={S.chipSep}>=</span>
                                <span style={S.chipVal}>{val.length > 20 ? val.slice(0, 20) + '…' : val}</span>
                              </>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                </>
              )}

            </div>

            {/* RIGHT — RECOMMENDED ACTIONS */}
            <div style={S.rightCol}>
              <div style={S.actionsLabel}>RECOMMENDED ACTIONS</div>
              <div style={S.stepsList}>
                {triage.recommendations.map((rec, i) => (
                  <div key={i} style={{ ...S.step, position: 'relative' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                      <div style={S.stepNum}>{String(i + 1).padStart(2, '0')}</div>
                      {i < triage.recommendations.length - 1 && (
                        <div style={{ width: '0.5px', flex: '1', minHeight: '8px', background: 'var(--border-bright)', margin: '2px 0' }} />
                      )}
                    </div>
                    <div style={{ ...S.stepText, paddingBottom: i === triage.recommendations.length - 1 ? '0' : '10px' }}>
                      {rec}
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>

          {/* ARBITER REASONING — full width bridge */}
          <div style={S.reasoningSection}>
            <div style={S.sectionLabel}>ARBITER REASONING</div>
            <div style={S.reasoningBody}>{triage.reasoning}</div>
          </div>

          {/* CONTAINMENT CTA — integrated footer */}
          <div style={S.containmentSection}>
            <div style={S.containmentLeft}>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '10px', color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
                Analysis complete. Ready to generate response.
              </div>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-muted)' }}>
                PowerShell · CMD · Investigation · Warnings
              </div>
            </div>
            <button
              style={S.containmentBtn}
              onClick={() => setContainmentOpen(true)}
              onMouseEnter={e => { e.currentTarget.style.opacity = '0.85' }}
              onMouseLeave={e => { e.currentTarget.style.opacity = '1' }}
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#080C14" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="4 17 10 11 4 5" />
                <line x1="12" y1="19" x2="20" y2="19" />
              </svg>
              <span style={S.containmentBtnLabel}>GENERATE CONTAINMENT PLAYBOOK</span>
            </button>
          </div>

        </div>
      )}

      {containmentOpen && result && (
        <ContainmentModal
          result={result}
          onClose={() => setContainmentOpen(false)}
        />
      )}
    </div>
  )
}