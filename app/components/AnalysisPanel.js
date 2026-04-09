'use client'
import { useState } from 'react'
import ContainmentModal from './ContainmentModal'

function Badge({ severity }) {
  return <span className={`arb-badge arb-${severity.toLowerCase()}`}>{severity}</span>
}

// Decision signal badges derived from triage data
function DecisionSignals({ triage, result }) {
  const signals = []

  if (result?.meta?.correlated)
    signals.push({ label: 'REDIS: REPEAT', color: '#E57373', bg: 'rgba(229,115,115,0.12)', icon: '↺' })
  if (result?.meta?.activeCampaign)
    signals.push({ label: 'CAMPAIGN ACTIVE', color: '#E57373', bg: 'rgba(229,115,115,0.18)', icon: '🔥' })
  if ((result?.meta?.correlationPatterns ?? []).some(p => p.type === 'user_multihost'))
    signals.push({ label: 'USER: MULTI-HOST', color: '#CE93D8', bg: 'rgba(206,147,216,0.12)', icon: '⬡' })
  if ((result?.meta?.correlationPatterns ?? []).some(p => p.type === 'ip_multitarget'))
    signals.push({ label: 'IP: MULTI-TARGET', color: '#E57373', bg: 'rgba(229,115,115,0.12)', icon: '⊕' })

  const enrichment = result?.enrichment
  const ips = result?.ips ?? []
  if (ips.length > 0) {
    const ip = enrichment?.[ips[0]]
    if (ip?.abuseipdb?.score >= 80)
      signals.push({ label: 'INTEL: MALICIOUS', color: 'var(--red)', bg: 'rgba(239,68,68,0.12)', icon: '⚑' })
    else if (ip?.abuseipdb?.score >= 40)
      signals.push({ label: 'INTEL: SUSPICIOUS', color: '#F59E0B', bg: 'rgba(245,158,11,0.12)', icon: '⚑' })
    else if (ips.length > 0)
      signals.push({ label: 'INTEL: CLEAN', color: 'var(--text-muted)', bg: 'transparent', icon: '✓' })
    if (ip?.abuseipdb?.isTorNode)
      signals.push({ label: 'TOR: CONFIRMED', color: 'var(--red)', bg: 'rgba(239,68,68,0.1)', icon: '⊘' })
  } else {
    signals.push({ label: 'INTEL: NO IP', color: 'var(--text-muted)', bg: 'transparent', icon: '—' })
  }

  if (triage.asset_is_critical)
    signals.push({ label: 'ASSET: CRITICAL', color: '#F59E0B', bg: 'rgba(245,158,11,0.1)', icon: '▲' })

  if (['CRITICAL', 'HIGH'].includes(triage.severity))
    signals.push({ label: `SEV: ${triage.severity}`, color: triage.severity === 'CRITICAL' ? 'var(--red)' : '#F59E0B', bg: triage.severity === 'CRITICAL' ? 'rgba(239,68,68,0.12)' : 'rgba(245,158,11,0.1)', icon: '⚡' })

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', padding: '8px 22px', borderBottom: '0.5px solid var(--border)', background: 'rgba(255,255,255,0.01)', alignItems: 'center' }}>
      <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.12em', marginRight: '8px', flexShrink: 0, borderRight: '0.5px solid var(--border-bright)', paddingRight: '8px' }}>DECISION SIGNALS</span>
      {signals.map((s, i) => (
        <span key={i} style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', fontWeight: '600', color: s.color, background: s.bg, border: `0.5px solid ${s.color}40`, borderRadius: '2px', padding: '3px 7px', letterSpacing: '0.08em', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
          <span style={{ fontSize: '9px' }}>{s.icon}</span>{s.label}
        </span>
      ))}
      {result?.meta?.correlated && !(result?.meta?.correlationPatterns?.length > 0) && (result?.meta?.uniqueAssets ?? 0) >= 2 && (
        <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', fontWeight: '600', color: '#CE93D8', background: 'rgba(206,147,216,0.12)', border: '0.5px solid rgba(206,147,216,0.4)', borderRadius: '2px', padding: '3px 7px', letterSpacing: '0.08em', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
          <span style={{ fontSize: '9px' }}>⬡</span>MULTI-ASSET
        </span>
      )}
      {(result?.meta?.correlationPatterns ?? []).filter(p => p?.type).map((p, i) => {
        const patternConfig = {
          user_multihost: { icon: '⬡', color: '#CE93D8', bg: 'rgba(206,147,216,0.12)', border: 'rgba(206,147,216,0.4)', label: `USER: ${p.assets?.length ?? '?'} HOSTS` },
          ip_multitarget: { icon: '⊕', color: '#E57373', bg: 'rgba(229,115,115,0.12)', border: 'rgba(229,115,115,0.4)', label: `IP: ${p.assets?.length ?? '?'} TARGETS` },
          user_ip_linked: { icon: '⟳', color: '#F59E0B', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.4)', label: 'LINKED INDICATORS' },
        }
        const cfg = patternConfig[p.type] ?? { icon: '◈', color: 'var(--text-muted)', bg: 'transparent', border: 'rgba(255,255,255,0.1)', label: p.type }
        return (
          <span key={`pattern-${i}`} style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', fontWeight: '600', color: cfg.color, background: cfg.bg, border: `0.5px solid ${cfg.border}`, borderRadius: '2px', padding: '3px 7px', letterSpacing: '0.08em', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <span style={{ fontSize: '9px' }}>{cfg.icon}</span>{cfg.label}
          </span>
        )
      })}
    </div>
  )
}

const S = {
  verdictHero: { padding: '14px 22px', borderBottom: '0.5px solid var(--border)', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '20px' },
  verdictLeft: { display: 'flex', flexDirection: 'column', gap: '5px', flex: '1' },
  verdictTitle: { fontSize: '22px', fontWeight: '500', color: 'var(--text-primary)', lineHeight: '1.1', letterSpacing: '-0.01em' },
  verdictSub: { fontFamily: 'var(--font-mono), monospace', fontSize: '10px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' },
  verdictRight: { display: 'flex', alignItems: 'center', gap: '20px', flexShrink: 0 },
  confBlock: { textAlign: 'right' },
  confBig: { fontFamily: 'var(--font-mono), monospace', fontSize: '32px', fontWeight: '600', color: 'var(--amber)', lineHeight: '1' },
  confUnit: { fontFamily: 'var(--font-mono), monospace', fontSize: '12px', color: 'var(--text-muted)' },
  confLabel: { fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)', letterSpacing: '0.12em', marginTop: '3px' },
  confBarWrap: { width: '64px', height: '2px', background: 'var(--border-bright)', borderRadius: '1px', overflow: 'hidden', marginTop: '4px', marginLeft: 'auto' },
  twoCol: { display: 'grid', gridTemplateColumns: '1fr 1fr', borderBottom: '0.5px solid var(--border)' },
  leftCol: { padding: '12px 16px', borderRight: '0.5px solid var(--border)', display: 'flex', flexDirection: 'column', gap: '12px' },
  rightCol: { padding: '12px 16px', display: 'flex', flexDirection: 'column', justifyContent: 'center' },
  metaBlock: { display: 'flex', flexDirection: 'column', gap: '2px' },
  sectionLabel: { fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.18em', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '5px' },
  metaId: { fontFamily: 'var(--font-mono), monospace', fontSize: '11px', color: 'var(--amber)', fontWeight: '500' },
  metaName: { fontSize: '12px', fontWeight: '500', color: 'var(--text-primary)', lineHeight: '1.3' },
  metaDetail: { fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-secondary)', marginTop: '2px' },
  assetName: { fontFamily: 'var(--font-mono), monospace', fontSize: '13px', fontWeight: '500', color: 'var(--text-primary)' },
  divider: { height: '0.5px', background: 'var(--border)' },
  evidenceChips: { display: 'flex', flexWrap: 'wrap', gap: '4px' },
  chip: { fontFamily: 'var(--font-mono), monospace', fontSize: '8px', background: 'var(--amber-15)', color: 'var(--amber)', border: '0.5px solid var(--amber-40)', borderRadius: '3px', padding: '2px 7px', display: 'flex', alignItems: 'center', gap: '4px' },
  chipSep: { color: 'rgba(245,158,11,0.35)' },
  chipVal: { color: 'var(--text-primary)', fontSize: '8px' },
  actionsLabel: { fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.18em', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px' },
  stepsList: { display: 'flex', flexDirection: 'column', flex: '1' },
  step: { display: 'flex', gap: '8px', alignItems: 'flex-start' },
  stepNum: { width: '16px', height: '16px', borderRadius: '50%', background: 'var(--bg-card)', border: '0.5px solid var(--amber-40)', color: 'var(--amber)', fontFamily: 'var(--font-mono), monospace', fontSize: '7px', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: '1px' },
  stepText: { fontSize: '11px', color: 'var(--text-secondary)', lineHeight: '1.45', paddingBottom: '8px', flex: '1', fontFamily: 'var(--font-mono), monospace' },
  reasoningSection: { padding: '12px 22px', borderBottom: '0.5px solid var(--border)' },
  containmentSection: { padding: '12px 22px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '16px' },
  containmentLeft: { display: 'flex', flexDirection: 'column', gap: '2px' },
  containmentBtnLabel: { fontFamily: 'var(--font-mono), monospace', fontSize: '10px', fontWeight: '500', color: '#080C14', letterSpacing: '0.08em', whiteSpace: 'nowrap' },
}

export default function AnalysisPanel({ alertText, setAlertText, result, loading, loadingPhase, error, onTriage, onReset }) {
  const triage        = result?.triage ?? null
  const decisionTrace = (() => {
    const raw = result?.meta?.decisionTrace ?? result?.meta?.deterministicOverrides ?? []
    return raw.filter(e => typeof e === 'object' && e.type)
  })()
  const signals       = result?.meta?.signals ?? []
  const [containmentOpen, setContainmentOpen] = useState(false)

  const isUrgent = triage?.severity === 'CRITICAL' || triage?.severity === 'HIGH'

  // Parse reasoning into sentences for structured display
  function parseReasoning(text) {
    if (!text) return []
    if (typeof text === 'object' && text.text) return parseReasoning(text.text)
    const str = Array.isArray(text) ? text.join(' ') : String(text)
    return str.split(/(?<=[.!?])\s+/).filter(s => s.trim().length > 0)
  }

  const reasoningSentences = parseReasoning(triage?.reasoning)
  const reasoningLabels = ['TECHNIQUE', 'INTELLIGENCE', 'RULE TRIGGERED', 'ACTION REQUIRED']

  return (
    <div className="arb-panel arb-analysis">

      {/* INPUT BLOCK */}
      <div className="arb-input-block">
        <div className="arb-input-header">
          <span className="arb-input-label">RAW ALERT INPUT</span>
          <label style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--amber)', letterSpacing: '0.08em', cursor: 'pointer', borderBottom: '0.5px solid var(--amber-40)', paddingBottom: '1px' }}>
            UPLOAD FILE
            <input type="file" accept=".txt,.log,.csv,.json,.xml,.evtx" style={{ display: 'none' }}
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
            <span>{error === 'RATE_LIMIT' ? 'API rate limit reached. Wait a few minutes and retry.' : error}</span>
            {error === 'RATE_LIMIT' && (
              <button onClick={onTriage} style={{ background:'none', border:'0.5px solid var(--red-40)', borderRadius:'3px', color:'var(--red)', fontFamily:'var(--font-mono),monospace', fontSize:'9px', letterSpacing:'0.08em', cursor:'pointer', padding:'3px 8px', whiteSpace:'nowrap', flexShrink:0 }}>RETRY</button>
            )}
          </div>
        )}
      </div>

      {/* LOADING */}
      {loading && (
        <div className="arb-loading">
          <div className="arb-loading-dot" />
          <span className="arb-loading-text">
            {loadingPhase === 'enriching' ? 'ENRICHING THREAT INTELLIGENCE...' : 'ARBITER IS ANALYZING YOUR ALERT'}
          </span>
        </div>
      )}

      {/* EMPTY STATE */}
      {!result && !loading && (
        <div style={{ padding: '36px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px', opacity: 0.5 }}>
          <svg viewBox="-8 0 136 120" width="28" height="25" xmlns="http://www.w3.org/2000/svg">
            <line x1="60" y1="8" x2="6" y2="112" stroke="#334055" strokeWidth="17" strokeLinecap="square"/>
            <line x1="60" y1="8" x2="114" y2="112" stroke="#334055" strokeWidth="17" strokeLinecap="square"/>
            <line x1="-6" y1="68" x2="126" y2="68" stroke="#334055" strokeWidth="7" strokeLinecap="square"/>
          </svg>
          <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '0.15em', textAlign: 'center', lineHeight: '1.8' }}>
            READY FOR TRIAGE<br/><span style={{ fontSize: '8px', opacity: 0.6 }}>PASTE AN ALERT AND CLICK ANALYZE</span>
          </div>
        </div>
      )}

      {triage && (
        <div>

          {/* VERDICT HERO */}
          <div style={S.verdictHero}>
            <div style={S.verdictLeft}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Badge severity={triage.severity} />
                {result?.meta?.correlated && (
                  <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.1em', color: '#080C14', background: '#E57373', borderRadius: '3px', padding: '2px 7px' }}>
                    CORRELATED ACTIVITY
                  </span>
                )}
              </div>
              <div style={S.verdictTitle}>{triage.classification}</div>
              <div style={S.verdictSub}>
                <span>{triage.tactic}</span>
                <span style={{ color: 'var(--border-bright)' }}>·</span>
                <span style={{ color: 'var(--amber)' }}>{triage.mitre_id}</span>
                {result?.meta?.processingTime && (
                  <><span style={{ color: 'var(--border-bright)' }}>·</span><span style={{ color: 'var(--text-muted)' }}>{(result.meta.processingTime / 1000).toFixed(1)}s</span></>
                )}
                {(result?.meta?.signals?.length ?? 0) > 0 && (
                  <><span style={{ color: 'var(--border-bright)' }}>·</span><span style={{ color: 'var(--text-muted)' }}>{result.meta.signals.length} SIGNAL{result.meta.signals.length !== 1 ? 'S' : ''}</span></>
                )}
                {result?.meta?.parseQuality && (
                  <><span style={{ color: 'var(--border-bright)' }}>·</span>
                  <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: result.meta.parseQuality === 'structured' ? '#4CAF50' : 'var(--red)', letterSpacing: '0.06em' }}>
                    {result.meta.parseQuality.toUpperCase()}
                  </span></>
                )}
              </div>
            </div>
            <div style={S.verdictRight}>
              <div style={S.confBlock}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px' }}>
                  <span style={S.confBig}>{triage.confidence}</span>
                  <span style={S.confUnit}>%</span>
                  {(() => {
                    const penalties = (result?.meta?.decisionTrace ?? result?.meta?.deterministicOverrides ?? [])
                      .filter(e => typeof e === 'object' && e.type === 'penalty')
                    const totalPenalty = penalties.reduce((sum, p) => sum + (p.value ?? 0), 0)
                    if (totalPenalty >= 0) return null
                    return (
                      <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--red)', letterSpacing: '0.04em' }}>
                        ▼{Math.abs(totalPenalty)}
                      </span>
                    )
                  })()}
                </div>
                <div style={S.confLabel}>CONFIDENCE</div>
                <div style={S.confBarWrap}>
                  <div style={{ height: '100%', background: 'var(--amber)', borderRadius: '1px', width: `${triage.confidence}%` }} />
                </div>
                {(() => {
                  const ct = decisionTrace.find(e => e.type === 'confidence')
                  if (!ct) return null
                  return (
                    <div style={{ marginTop: '6px', display: 'flex', flexDirection: 'column', gap: '2px' }}>
                      {ct.base        != null && <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>BASE <span style={{ color: 'var(--text-secondary)' }}>{ct.base}%</span></div>}
                      {ct.campaignBonus  != null && <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>CAMPAIGN <span style={{ color: '#E57373' }}>+{ct.campaignBonus}%</span></div>}
                      {ct.unknownPenalty != null && <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>UNKNOWN <span style={{ color: 'var(--text-muted)' }}>−{ct.unknownPenalty}%</span></div>}
                    </div>
                  )
                })()}
              </div>
            </div>
          </div>

          {/* DECISION SIGNALS */}
          <DecisionSignals triage={triage} result={result} />

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
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{
                    ...S.assetName,
                    color: triage.asset_is_critical ? '#F59E0B' : 'var(--text-primary)',
                    textShadow: triage.asset_is_critical ? '0 0 12px rgba(245,158,11,0.4)' : 'none',
                  }}>{triage.affected_asset}</div>
                  {triage.asset_is_critical && (
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                  )}
                </div>
                <span style={{
                  fontFamily: 'var(--font-mono), monospace',
                  fontSize: '7px',
                  letterSpacing: '0.1em',
                  color: triage.asset_is_critical ? '#E57373' : 'var(--text-muted)',
                  background: triage.asset_is_critical ? 'rgba(229,115,115,0.12)' : 'rgba(255,255,255,0.04)',
                  border: `0.5px solid ${triage.asset_is_critical ? 'rgba(229,115,115,0.4)' : 'rgba(255,255,255,0.08)'}`,
                  borderRadius: '2px',
                  padding: '2px 6px',
                  marginTop: '5px',
                  display: 'inline-block',
                }}>
                  {triage.asset_is_critical ? '⚠ CRITICAL ASSET' : 'STANDARD ASSET'}
                </span>
              </div>
              {triage.evidence?.length > 0 && (
                <>
                  <div style={S.divider} />
                  <div>
                    <div style={S.sectionLabel}>EVIDENCE</div>
                    <div style={S.evidenceChips}>
                      {(triage.evidence ?? []).map((item, i) => {
                        const eqIdx = item.indexOf('=')
                        const field = eqIdx > -1 ? item.slice(0, eqIdx) : item
                        const val   = eqIdx > -1 ? item.slice(eqIdx + 1) : ''
                        return (
                          (() => {
                            const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(val) || field.toLowerCase().includes('ip') || field.toLowerCase().includes('address')
                            const isUser = field.toLowerCase().includes('user') || field.toLowerCase().includes('subject') || field.toLowerCase().includes('target')
                            const chipColor = isIP ? '#64B5F6' : isUser ? '#CE93D8' : 'var(--amber)'
                            const chipBg = isIP ? 'rgba(100,181,246,0.1)' : isUser ? 'rgba(206,147,216,0.1)' : 'var(--amber-15)'
                            const chipBorder = isIP ? 'rgba(100,181,246,0.3)' : isUser ? 'rgba(206,147,216,0.3)' : 'var(--amber-40)'
                            return (
                              <div key={i} style={{ ...S.chip, color: chipColor, background: chipBg, border: `0.5px solid ${chipBorder}` }}>
                                <span>{field}</span>
                                {val && <><span style={{ color: `${chipColor}50` }}>=</span><span style={{ color: 'var(--text-primary)', fontSize: '8px' }}>{val.length > 20 ? val.slice(0, 20) + '…' : val}</span></>}
                              </div>
                            )
                          })()
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
                {(triage.recommendations ?? []).map((rec, i) => {
                  const prov = triage.recommendation_provenance?.[i]
                  const provColors = { enrichment_confirmed: 'var(--amber)', behavioral_heuristic: '#6B7FD4', account_action: '#E57373', forensic: '#9E9E9E', known_good_override: '#4CAF50' }
                  const provLabels = { enrichment_confirmed: 'CTI', behavioral_heuristic: 'HEURISTIC', account_action: 'ACCOUNT', forensic: 'FORENSIC', known_good_override: 'KNOWN-GOOD' }
                  return (
                    <div key={i} style={{ ...S.step, position: 'relative' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                        <div style={S.stepNum}>{String(i + 1).padStart(2, '0')}</div>
                        {i < triage.recommendations.length - 1 && <div style={{ width: '0.5px', flex: '1', minHeight: '6px', background: 'var(--border-bright)', margin: '2px 0' }} />}
                      </div>
                      <div style={{ flex: 1, paddingBottom: i === triage.recommendations.length - 1 ? 0 : '8px' }}>
                        <div style={S.stepText}>{rec}</div>
                        {prov && (
                          <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: provColors[prov] ?? 'var(--text-muted)', letterSpacing: '0.1em', marginTop: '-4px', paddingBottom: '4px' }}>▲ {provLabels[prov] ?? prov}</div>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>

          {/* ENGINE DECISION TRACE */}
          {decisionTrace.length > 0 && (
            <div style={{ ...S.reasoningSection, marginBottom: 0, paddingBottom: '14px', borderBottom: '0.5px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={S.sectionLabel}>ENGINE DECISION TRACE</div>
                <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
                  {(result?.meta?.signals ?? []).length} SIGNAL{(result?.meta?.signals ?? []).length !== 1 ? 'S' : ''} · {result?.meta?.parseQuality?.toUpperCase() ?? 'UNKNOWN'} PARSE
                </span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {(decisionTrace ?? []).map((e, i) => {
                  const typeColors = { dominant: 'var(--amber)', severity: 'var(--red)', classification: '#6B7FD4', asset: '#F59E0B', confidence: 'var(--text-muted)', supporting: 'var(--text-muted)', penalty: 'var(--red)' }
                  if (typeof e === 'string') e = { type: 'supporting', label: e }
                  if (!e.type) e = { ...e, type: 'supporting' }
                  const color = typeColors[e.type] ?? 'var(--text-muted)'
                  return (
                    <div key={i} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', padding: e.type === 'dominant' ? '6px 8px' : '2px 0', background: e.type === 'dominant' ? 'rgba(245,158,11,0.08)' : 'transparent', borderRadius: e.type === 'dominant' ? '3px' : '0', borderLeft: e.type === 'dominant' ? '2px solid var(--amber)' : 'none', paddingLeft: e.type === 'dominant' ? '10px' : '0' }}>
                      <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color, letterSpacing: '0.1em', minWidth: '80px', paddingTop: '1px', textTransform: 'uppercase', opacity: 0.8, fontWeight: e.type === 'dominant' ? '700' : '400' }}>{e.type}</span>
                      <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: e.type === 'dominant' ? '10px' : '9px', color: e.type === 'dominant' ? 'var(--amber)' : 'var(--text-secondary)', lineHeight: '1.5', flex: 1, fontWeight: e.type === 'dominant' ? '600' : '400' }}>
                        {e.label}
                        {e.rule && <span style={{ color: 'var(--text-muted)', fontSize: '8px', fontWeight: '400' }}> [{e.rule}]</span>}
                        {e.type === 'confidence' && e.base !== undefined && (
                          <span style={{ color: 'var(--text-muted)', fontSize: '8px' }}> (base={e.base}, campaign=+{e.campaignBonus ?? 0}, parse=+{e.parseBonus ?? 0})</span>
                        )}
                      </span>
                      {e.severity && <span className={`arb-badge arb-${e.severity?.toLowerCase()}`} style={{ fontSize: '7px', flexShrink: 0 }}>{e.severity}</span>}
                      {e.type === 'penalty' && e.value && <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--red)', flexShrink: 0 }}>{e.value}</span>}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* STRUCTURED REASONING */}
          <div style={S.reasoningSection}>
            <div style={S.sectionLabel}>ARBITER REASONING</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
              {reasoningSentences.map((sentence, i) => (
                <div key={i} style={{ display: 'flex', gap: '10px', padding: '7px 0', borderBottom: i < reasoningSentences.length - 1 ? '0.5px solid var(--border)' : 'none' }}>
                  <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--amber)', letterSpacing: '0.1em', minWidth: '90px', paddingTop: '1px', opacity: 0.7 }}>
                    {reasoningLabels[i] ?? `POINT ${i + 1}`}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: '1.6', flex: 1 }}>{sentence}</div>
                </div>
              ))}
            </div>
          </div>

          {/* CONTAINMENT CTA */}
          <div style={S.containmentSection}>
            <div style={S.containmentLeft}>
              <div style={{ display: 'flex', gap: '10px', marginBottom: '5px' }}>
                {[
                  { label: 'Triage Ready', ok: true },
                  { label: 'Intel Verified', ok: (result?.ips?.length > 0) },
                  { label: 'Assets Mapped', ok: !!(triage.affected_asset && triage.affected_asset !== 'UNKNOWN' && triage.affected_asset !== '') },
                ].map((item, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '3px' }}>
                    <span style={{ color: item.ok ? '#4CAF50' : 'var(--text-muted)', fontSize: '9px' }}>{item.ok ? '✓' : '○'}</span>
                    <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: item.ok ? 'var(--text-secondary)' : 'var(--text-muted)', letterSpacing: '0.06em' }}>{item.label}</span>
                  </div>
                ))}
              </div>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-muted)' }}>
                PowerShell · CMD · Investigation · Warnings
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
              {result && (
                <button
                  onClick={() => {
                    const forensic = {
                      case_id: result?.meta?.alertType ?? 'UNKNOWN',
                      timestamp: new Date().toISOString(),
                      severity: triage.severity,
                      classification: triage.classification,
                      confidence: triage.confidence,
                      mitre_id: triage.mitre_id,
                      mitre_name: triage.mitre_name,
                      affected_asset: triage.affected_asset,
                      asset_is_critical: triage.asset_is_critical,
                      evidence: triage.evidence,
                      signals: result?.meta?.signals ?? [],
                      decision_trace: result?.meta?.deterministicOverrides ?? [],
                      recommendations: triage.recommendations,
                      enrichment_sources: result?.meta?.enrichmentSources ?? [],
                      correlated: result?.meta?.correlated ?? false,
                      parse_quality: result?.meta?.parseQuality ?? 'unknown',
                    }
                    navigator.clipboard.writeText(JSON.stringify(forensic, null, 2))
                  }}
                  style={{ background: 'none', border: '0.5px solid var(--border-bright)', borderRadius: '3px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.08em', cursor: 'pointer', padding: '6px 10px', whiteSpace: 'nowrap', transition: 'all 0.15s' }}
                  onMouseEnter={e => { e.currentTarget.style.color = 'var(--text-secondary)'; e.currentTarget.style.borderColor = 'var(--text-muted)' }}
                  onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'var(--border-bright)' }}
                >
                  ⬡ FORENSIC
                </button>
              )}
              <button
                style={{
                  display: 'flex', alignItems: 'center', gap: '10px',
                  background: isUrgent ? 'var(--red)' : 'var(--amber)',
                  border: 'none', borderRadius: '4px', padding: '9px 18px',
                  cursor: 'pointer', flexShrink: 0,
                  animation: isUrgent ? 'arbBtnPulse 2s ease-in-out infinite' : 'none',
                }}
                onClick={() => setContainmentOpen(true)}
                onMouseEnter={e => { e.currentTarget.style.opacity = '0.85'; e.currentTarget.style.animation = 'none' }}
                onMouseLeave={e => { e.currentTarget.style.opacity = '1'; e.currentTarget.style.animation = isUrgent ? 'arbBtnPulse 2s ease-in-out infinite' : 'none' }}
              >
                <style>{`@keyframes arbBtnPulse { 0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,0.4)}50%{box-shadow:0 0 0 6px rgba(239,68,68,0)} }`}</style>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#080C14" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" />
                </svg>
                <span style={S.containmentBtnLabel}>GENERATE CONTAINMENT PLAYBOOK</span>
              </button>
            </div>
          </div>

        </div>
      )}

      {containmentOpen && result && (
        <ContainmentModal result={result} onClose={() => setContainmentOpen(false)} />
      )}
    </div>
  )
}