'use client'

function ScoreBar({ value, max = 100, color = 'red' }) {
  return (
    <div className="arb-bar">
      <div
        className={`arb-bar-fill ${color === 'amber' ? 'arb-bar-amber' : 'arb-bar-red'}`}
        style={{ width: `${(value / max) * 100}%` }}
      />
    </div>
  )
}

export default function IntelPanel({ result, collapsed, onToggle }) {
  const { enrichment, ips } = result ?? {}
  const primaryIP = ips?.[0] ?? null
  const intel     = primaryIP ? enrichment?.[primaryIP] : null
  const abuse     = intel?.abuseipdb ?? null
  const vt        = intel?.virustotal ?? null
  const otx       = intel?.otx ?? null

  return (
    <div className={`arb-panel arb-intel${collapsed ? ' arb-panel-collapsed' : ''}`}>
      <div className="arb-panel-header">
        <button className="arb-collapse-btn" onClick={onToggle}>
          {collapsed ? '‹' : '›'}
        </button>
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
              <div className="arb-ip-address">{primaryIP}</div>
              {abuse && (
                <div className="arb-meta-list">
                  <div className="arb-meta-row"><span className="arb-mk">COUNTRY</span><span className="arb-mv">{abuse.country ?? '—'}</span></div>
                  <div className="arb-meta-row"><span className="arb-mk">ISP</span><span className="arb-mv arb-mv-bad">{abuse.isp ?? '—'}</span></div>
                  {vt && <>
                    <div className="arb-meta-row"><span className="arb-mk">ASN</span><span className="arb-mv">{vt.asn ? `AS${vt.asn}` : '—'}</span></div>
                    <div className="arb-meta-row"><span className="arb-mk">AS OWNER</span><span className="arb-mv">{vt.asOwner ?? '—'}</span></div>
                  </>}
                  {abuse.isTorNode && (
                    <div className="arb-meta-row"><span className="arb-mk">TYPE</span><span className="arb-mv arb-mv-bad">Tor Exit Node</span></div>
                  )}
                </div>
              )}
            </div>

            {abuse && (
              <div className="arb-section">
                <div className="arb-card-label">AbuseIPDB Score</div>
                <div className="arb-score-header">
                  <div><span className="arb-score-num">{abuse.score}</span><span className="arb-score-denom"> /100</span></div>
                  <span className={`arb-badge ${abuse.score >= 80 ? 'arb-critical' : abuse.score >= 40 ? 'arb-high' : 'arb-low'}`}>
                    {abuse.score >= 80 ? 'MALICIOUS' : abuse.score >= 40 ? 'SUSPICIOUS' : 'CLEAN'}
                  </span>
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
                {otx.malwareFamily && (
                  <div className="arb-meta-row" style={{ marginBottom: '10px' }}>
                    <span className="arb-mk">MALWARE</span>
                    <span className="arb-mv arb-mv-bad">{otx.malwareFamily}</span>
                  </div>
                )}
                {otx.tags?.length > 0 && (
                  <div className="arb-tags">
                    {otx.tags.slice(0, 6).map((tag, i) => (
                      <span key={i} className="arb-tag arb-tag-danger">{tag}</span>
                    ))}
                  </div>
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
          </>
        )}
      </div>
    </div>
  )
}