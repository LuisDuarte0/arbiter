'use client'
import { useState } from 'react'

function ScoreBar({ value, max = 100, color = 'red' }) {
  return (
    <div className="arb-bar">
      <div className={`arb-bar-fill ${color === 'amber' ? 'arb-bar-amber' : 'arb-bar-red'}`} style={{ width: `${(value / max) * 100}%` }} />
    </div>
  )
}

function DefangButton({ ip }) {
  const [copied, setCopied] = useState(false)
  const defanged = ip.replace(/\./g, '[.]')
  function copy() {
    navigator.clipboard.writeText(defanged).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })
  }
  return (
    <button onClick={copy} title={`Copy defanged: ${defanged}`} style={{ background: 'none', border: '0.5px solid var(--border-bright)', borderRadius: '2px', color: copied ? '#00ff41' : 'var(--text-muted)', fontFamily: 'var(--font-mono), monospace', fontSize: '7px', letterSpacing: '0.08em', cursor: 'pointer', padding: '2px 5px', transition: 'all 0.15s', flexShrink: 0 }}>
      {copied ? 'COPIED' : 'DEFANG'}
    </button>
  )
}

function ConsensusBadge({ abuse, vt, otx, correlation }) {
  const maliciousCount = [abuse?.score >= 80, vt?.malicious >= 5, otx?.pulseCount > 10].filter(Boolean).length
  const isHighVolume = correlation?.hits?.some(h => h.count >= 3)
  const isPersistent = correlation?.hits?.some(h => h.count >= 2)
  const badges = []
  if (maliciousCount >= 3) badges.push({ label: 'MALICIOUS CONSENSUS', color: 'var(--red)', bg: 'rgba(239,68,68,0.12)' })
  else if (maliciousCount === 2) badges.push({ label: 'CROSS-VALIDATED', color: '#F59E0B', bg: 'rgba(245,158,11,0.12)' })
  if (abuse?.isTorNode) badges.push({ label: 'TOR EXIT NODE', color: 'var(--red)', bg: 'rgba(239,68,68,0.1)' })
  if (isHighVolume) badges.push({ label: 'VOLUMETRIC', color: '#E57373', bg: 'rgba(229,115,115,0.12)' })
  else if (isPersistent) badges.push({ label: 'PERSISTENT THREAT', color: '#F59E0B', bg: 'rgba(245,158,11,0.1)' })
  if (!badges.length) return null
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '8px' }}>
      {badges.map((b, i) => (
        <span key={i} style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: b.color, background: b.bg, border: `0.5px solid ${b.color}40`, borderRadius: '2px', padding: '2px 6px', letterSpacing: '0.08em' }}>{b.label}</span>
      ))}
    </div>
  )
}

export default function IntelPanel({ result, collapsed, onToggle, indicatorCache, onIpFilter }) {
  const { enrichment, ips, correlation } = result ?? {}
  const primaryIP = ips?.[0] ?? null
  const intel      = primaryIP ? enrichment?.[primaryIP] : null
  const abuse      = intel?.abuseipdb ?? null
  const vt         = intel?.virustotal ?? null
  const otx        = intel?.otx ?? null
  const cached     = primaryIP ? indicatorCache?.[primaryIP] : null

  const redisHit    = correlation?.hits?.find(h => h.key === `ip:${primaryIP}`)
  const isFirstSeen = !redisHit
  const isPersistent = redisHit && redisHit.count >= 2
  const isVolumetric = redisHit && redisHit.count >= 3

  return (
    <div className={`arb-panel arb-intel${collapsed ? ' arb-panel-collapsed' : ''}`}>
      <div className="arb-panel-header">
        <button className="arb-collapse-btn" onClick={onToggle}>{collapsed ? '‹' : '›'}</button>
        {!collapsed && <span className="arb-panel-title">Threat Intelligence</span>}
        {!collapsed && (
          <span className="arb-panel-badge">
            {result ? `${ips?.length ?? 0} IP${ips?.length !== 1 ? 'S' : ''} ANALYZED` : 'PENDING'}
          </span>
        )}
      </div>

      <div className="arb-panel-content">
        {!result && (
          <div className="arb-empty">
            <svg viewBox="-8 0 136 120" width="36" height="32" xmlns="http://www.w3.org/2000/svg">
              <line x1="60" y1="8" x2="6" y2="112" stroke="#334055" strokeWidth="17" strokeLinecap="square"/>
              <line x1="60" y1="8" x2="114" y2="112" stroke="#334055" strokeWidth="17" strokeLinecap="square"/>
              <line x1="-6" y1="68" x2="126" y2="68" stroke="#334055" strokeWidth="7" strokeLinecap="square"/>
            </svg>
            <div className="arb-empty-text">Submit an alert to populate threat intelligence</div>
          </div>
        )}

        {result && !primaryIP && (
          <div className="arb-section">
            <div className="arb-card-label">NOTE</div>
            <div className="arb-note-text">No public IPs detected. Enrichment unavailable.</div>
          </div>
        )}

        {result && primaryIP && (
          <>
            <div className="arb-section">
              <div className="arb-card-label">Source IP</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                <div className="arb-ip-address" style={{ margin: 0 }}>{primaryIP}</div>
                <DefangButton ip={primaryIP} />
                <button
                onClick={() => onIpFilter?.(primaryIP)}
                style={{ background: 'none', border: '0.5px solid rgba(100,149,237,0.4)', borderRadius: '2px', color: 'cornflowerblue', fontFamily: 'var(--font-mono), monospace', fontSize: '7px', letterSpacing: '0.08em', cursor: 'pointer', padding: '2px 5px' }}
              >
                PIVOT
              </button>
              </div>

              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginBottom: '4px' }}>
                {isFirstSeen && <span style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)', border: '0.5px solid var(--border-bright)', borderRadius: '2px', padding: '2px 6px', letterSpacing: '0.08em' }}>FIRST SEEN</span>}
                {isVolumetric && <span style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: '#E57373', background: 'rgba(229,115,115,0.1)', border: '0.5px solid rgba(229,115,115,0.3)', borderRadius: '2px', padding: '2px 6px', letterSpacing: '0.08em' }}>VOLUMETRIC</span>}
                {isPersistent && !isVolumetric && <span style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: '#F59E0B', background: 'rgba(245,158,11,0.1)', border: '0.5px solid rgba(245,158,11,0.3)', borderRadius: '2px', padding: '2px 6px', letterSpacing: '0.08em' }}>PERSISTENT THREAT</span>}
              </div>

              {cached && cached.seenCount > 1 && (
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', marginBottom: '6px', background: 'rgba(245,158,11,0.15)', border: '0.5px solid var(--amber-40)', borderRadius: '3px', padding: '3px 8px' }}>
                  <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: 'var(--amber)' }} />
                  <span style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '8px', color: 'var(--amber)', letterSpacing: '0.1em' }}>SEEN {cached.seenCount}× THIS SESSION</span>
                </div>
              )}

              <ConsensusBadge abuse={abuse} vt={vt} otx={otx} correlation={correlation} />

              {abuse && (
                <div className="arb-meta-list" style={{ marginTop: '8px' }}>
                  <div className="arb-meta-row"><span className="arb-mk">COUNTRY</span><span className="arb-mv">{abuse.country ?? '—'}</span></div>
                  <div className="arb-meta-row"><span className="arb-mk">ISP</span><span className="arb-mv arb-mv-bad">{abuse.isp ?? '—'}</span></div>
                  {vt && <>
                    <div className="arb-meta-row"><span className="arb-mk">ASN</span><span className="arb-mv">{vt.asn ? `AS${vt.asn}` : '—'}</span></div>
                    <div className="arb-meta-row"><span className="arb-mk">AS OWNER</span><span className="arb-mv">{vt.asOwner ?? '—'}</span></div>
                  </>}
                  {abuse.isTorNode && <div className="arb-meta-row"><span className="arb-mk">TYPE</span><span className="arb-mv arb-mv-bad">Tor Exit Node</span></div>}
                </div>
              )}
            </div>

            {abuse && (
              <div className="arb-section">
                <div className="arb-card-label">AbuseIPDB Score</div>
                <div className="arb-score-header">
                  <div><span className="arb-score-num">{abuse.score}</span><span className="arb-score-denom"> /100</span></div>
                  <span className={`arb-badge ${abuse.score >= 80 ? 'arb-critical' : abuse.score >= 40 ? 'arb-high' : 'arb-low'}`}>{abuse.score >= 80 ? 'MALICIOUS' : abuse.score >= 40 ? 'SUSPICIOUS' : 'CLEAN'}</span>
                </div>
                <ScoreBar value={abuse.score} />
                <div className="arb-score-sub">{abuse.totalReports} REPORTS IN LAST 30 DAYS</div>
              </div>
            )}

            {vt && (
              <div className="arb-section">
                <div className="arb-card-label">VirusTotal</div>
                <div className="arb-vt-row">
                  <div><span className="arb-vt-count">{vt.malicious}</span><span className="arb-vt-denom"> / {vt.total} engines</span></div>
                  <span className={`arb-badge ${vt.malicious > 0 ? 'arb-high' : 'arb-low'}`}>{vt.malicious > 0 ? 'FLAGGED' : 'CLEAN'}</span>
                </div>
                <ScoreBar value={vt.malicious} max={Math.max(vt.total, 1)} />
                <div className="arb-score-sub">{vt.suspicious} SUSPICIOUS · {vt.total} TOTAL ENGINES</div>
              </div>
            )}

            {otx && (
              <div className="arb-section">
                <div className="arb-card-label">AlienVault OTX</div>
                <div className="arb-meta-row" style={{ marginBottom: '10px' }}>
                  <span className="arb-mk">PULSE COUNT</span>
                  <span className={`arb-mv ${otx.pulseCount > 0 ? 'arb-mv-bad' : ''}`}>{otx.pulseCount} PULSES</span>
                </div>
                {otx.malwareFamily && <div className="arb-meta-row" style={{ marginBottom: '10px' }}><span className="arb-mk">MALWARE</span><span className="arb-mv arb-mv-bad">{otx.malwareFamily}</span></div>}
                {otx.tags?.length > 0 && (
                  <div className="arb-tags">{otx.tags.slice(0, 6).map((tag, i) => <span key={i} className="arb-tag arb-tag-danger">{tag}</span>)}</div>
                )}
              </div>
            )}

            {ips.length > 1 && (
              <div className="arb-section">
                <div className="arb-card-label">Additional IPs</div>
                {ips.slice(1).map((ip, i) => (
                  <div key={i} className="arb-meta-row">
                    <span className="arb-mk">{ip}</span>
                    <span className="arb-mv">{enrichment[ip]?.abuseipdb?.score != null ? `${enrichment[ip].abuseipdb.score}/100` : '—'}</span>
                  </div>
                ))}
              </div>
            )}

            {correlation?.hits?.length > 0 && (
              <div className="arb-section" style={{ borderTop: '0.5px solid var(--border)', paddingTop: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div className="arb-card-label" style={{ color: '#E57373', marginBottom: 0 }}>ARBITER MEMORY</div>
                  {result?.meta?.activeCampaign && <span style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', background: '#E57373', color: '#080C14', borderRadius: '2px', padding: '2px 6px', letterSpacing: '0.1em' }}>ACTIVE CAMPAIGN</span>}
                </div>
                {result?.meta?.uniqueAssets > 1 && <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '8px', color: '#E57373', marginBottom: '8px' }}>BLAST RADIUS: {result.meta.uniqueAssets} UNIQUE ASSETS HIT</div>}
                {correlation.hits.map((h, i) => {
                  const age = Math.round((Date.now() - h.timestamp) / 60000)
                  const indicator = h.key?.startsWith('ip:') ? `IP ${h.key.slice(3)}` : `User ${h.key?.slice(5)}`
                  return (
                    <div key={i} style={{ marginBottom: '10px', paddingBottom: '10px', borderBottom: i < correlation.hits.length - 1 ? '0.5px solid var(--border)' : 'none' }}>
                      <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '9px', color: '#E57373', marginBottom: '4px' }}>{indicator}</div>
                      <div className="arb-meta-row"><span className="arb-mk">SEEN</span><span className="arb-mv arb-mv-bad">{h.count}× IN LAST 24H</span></div>
                      <div className="arb-meta-row"><span className="arb-mk">LAST SEVERITY</span><span className="arb-mv">{h.severity}</span></div>
                      <div className="arb-meta-row"><span className="arb-mk">LAST SEEN</span><span className="arb-mv">{age}min ago</span></div>
                      {h.assets?.length > 0 && (
                        <div style={{ marginTop: '6px' }}>
                          <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.12em', marginBottom: '3px' }}>ASSET TRAIL</div>
                          {h.assets.map((asset, j) => (
                            <div key={j} style={{ display: 'flex', alignItems: 'center', gap: '5px', marginBottom: '2px' }}>
                              <div style={{ width: '4px', height: '4px', borderRadius: '50%', background: j === 0 ? '#E57373' : 'var(--text-muted)', flexShrink: 0 }} />
                              <span style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '8px', color: j === 0 ? '#E57373' : 'var(--text-muted)' }}>{asset}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}

            {correlation?.hits?.length > 0 && (() => {
              const allCases = correlation.hits.flatMap(h =>
                (h.cases ?? []).map(caseId => ({ caseId, severity: h.severity, indicator: h.key?.startsWith('ip:') ? h.key.slice(3) : h.key?.slice(5) }))
              ).slice(0, 8)
              if (!allCases.length) return null
              return (
                <div className="arb-section" style={{ borderTop: '0.5px solid var(--border)', paddingTop: '12px' }}>
                  <div className="arb-card-label" style={{ marginBottom: '8px' }}>CAMPAIGN TIMELINE</div>
                  {allCases.map((c, i) => (
                    <div key={i} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', marginBottom: '6px' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                        <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: c.severity === 'CRITICAL' ? 'var(--red)' : c.severity === 'HIGH' ? 'var(--amber)' : 'var(--text-muted)', marginTop: '2px' }} />
                        {i < allCases.length - 1 && <div style={{ width: '1px', height: '14px', background: 'var(--border-bright)' }} />}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '8px', color: 'var(--text-secondary)' }}>{c.caseId.slice(4, 17)}</div>
                        <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)' }}>{c.indicator}</div>
                      </div>
                      <span className={`arb-badge arb-${c.severity?.toLowerCase()}`} style={{ fontSize: '7px' }}>{c.severity}</span>
                    </div>
                  ))}
                </div>
              )
            })()}
          </>
        )}
      </div>
    </div>
  )
}