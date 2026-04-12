import { useState, useEffect } from 'react'

export default function ContainmentModal({ result, onClose }) {
  const { triage, enrichment, ips } = result ?? {}
  const signals = result?.meta?.signals ?? []

  const [playbook, setPlaybook]       = useState(null)
  const [loading, setLoading]         = useState(true)
  const [error, setError]             = useState(null)
  const [copied, setCopied]           = useState(false)
  const [activePhase, setActivePhase] = useState('phase1')

  useEffect(() => {
    async function generate() {
      try {
        const res = await fetch('/api/containment', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ triage, enrichment, ips, signals }),
        })
        const data = await res.json()
        if (data.error) throw new Error(data.error)
        setPlaybook(data.playbook)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    generate()
  }, [])

  const isTraceRequired = triage?.verdict_reliability_class !== 'SURFACE_SAFE'

  function getActiveSteps() {
    if (!playbook) return []
    if (activePhase === 'phase1') return playbook.phase1.steps
    if (activePhase === 'phase2') return playbook.phase2.steps
    if (activePhase === 'phase3') return playbook.phase3.steps
    return []
  }

  function handleCopy() {
    const steps = getActiveSteps()
    if (!steps.length) return
    const text = steps.map((s, i) => `${String(i + 1).padStart(2, '0')}. ${s}`).join('\n')
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const phase3Blocked = playbook?.phase3?.blocked ?? isTraceRequired

  const S = {
    overlay: {
      position: 'fixed', inset: 0,
      background: 'rgba(8,12,20,0.85)',
      backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 1000, padding: '20px',
    },
    modal: {
      background: 'var(--bg-card)',
      border: '0.5px solid var(--border-bright)',
      borderRadius: '8px',
      width: '100%', maxWidth: '860px',
      maxHeight: '88vh',
      display: 'flex', flexDirection: 'column',
      overflow: 'hidden',
    },
    header: {
      padding: '16px 22px',
      borderBottom: '0.5px solid var(--border)',
      display: 'flex', alignItems: 'center',
      justifyContent: 'space-between',
    },
    headerLeft: { display: 'flex', flexDirection: 'column', gap: '4px' },
    title: {
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '11px', letterSpacing: '0.18em',
      color: 'var(--text-primary)', fontWeight: '600',
    },
    subtitle: {
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '8px', letterSpacing: '0.12em',
      color: 'var(--text-muted)',
    },
    closeBtn: {
      background: 'none', border: 'none',
      color: 'var(--text-muted)', cursor: 'pointer',
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '10px', letterSpacing: '0.1em',
      padding: '4px 8px',
    },
    body: {
      display: 'flex', flex: 1, overflow: 'hidden',
    },
    sidebar: {
      width: '200px', flexShrink: 0,
      borderRight: '0.5px solid var(--border)',
      padding: '16px 14px',
      display: 'flex', flexDirection: 'column', gap: '12px',
      overflowY: 'auto',
    },
    metaItem: { display: 'flex', flexDirection: 'column', gap: '2px' },
    metaLabel: {
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '7px', letterSpacing: '0.1em',
      color: 'var(--text-muted)',
    },
    metaValue: {
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '9px', color: 'var(--text-secondary)',
    },
    divider: {
      height: '0.5px', background: 'var(--border)',
      margin: '4px 0',
    },
    main: {
      flex: 1, display: 'flex', flexDirection: 'column',
      overflow: 'hidden',
    },
    phases: {
      display: 'flex', gap: '0',
      borderBottom: '0.5px solid var(--border)',
    },
    phaseBtn: (active, blocked) => ({
      flex: 1, padding: '10px 8px',
      background: 'none', border: 'none',
      borderBottom: active
        ? blocked ? '2px solid var(--red)' : '2px solid var(--amber)'
        : '2px solid transparent',
      color: active
        ? blocked ? 'var(--red)' : 'var(--amber)'
        : 'var(--text-muted)',
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '7px', letterSpacing: '0.1em',
      cursor: 'pointer',
      opacity: blocked && !active ? 0.5 : 1,
    }),
    content: {
      flex: 1, overflowY: 'auto',
      padding: '16px 22px',
    },
    phaseNote: {
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '8px', color: 'var(--text-muted)',
      marginBottom: '14px', lineHeight: '1.6',
      padding: '8px 12px',
      background: 'rgba(255,255,255,0.02)',
      borderLeft: '2px solid var(--border-bright)',
      borderRadius: '0 3px 3px 0',
    },
    blockedBox: {
      padding: '16px',
      background: 'rgba(239,68,68,0.06)',
      border: '0.5px solid rgba(239,68,68,0.3)',
      borderRadius: '4px',
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '9px', color: 'var(--red)',
      lineHeight: '1.7',
    },
    stepsList: {
      display: 'flex', flexDirection: 'column', gap: '0',
    },
    step: {
      display: 'flex', gap: '12px',
      alignItems: 'flex-start',
      padding: '10px 0',
      borderBottom: '0.5px solid rgba(255,255,255,0.04)',
    },
    stepNum: {
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '8px', color: 'var(--amber)',
      letterSpacing: '0.08em', flexShrink: 0,
      minWidth: '20px',
    },
    stepText: {
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '10px', color: 'var(--text-secondary)',
      lineHeight: '1.7', flex: 1,
    },
    footer: {
      padding: '12px 22px',
      borderTop: '0.5px solid var(--border)',
      display: 'flex', alignItems: 'center',
      justifyContent: 'space-between',
    },
    reliabilityBadge: {
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '7px', letterSpacing: '0.1em',
      color: isTraceRequired ? 'var(--amber)' : 'var(--green)',
      background: isTraceRequired ? 'rgba(245,158,11,0.1)' : 'rgba(34,197,94,0.1)',
      border: `0.5px solid ${isTraceRequired ? 'rgba(245,158,11,0.3)' : 'rgba(34,197,94,0.3)'}`,
      borderRadius: '2px', padding: '2px 8px',
    },
    copyBtn: {
      background: 'none',
      border: '0.5px solid var(--border-bright)',
      borderRadius: '3px',
      color: copied ? 'var(--green)' : 'var(--text-muted)',
      fontFamily: 'var(--font-mono), monospace',
      fontSize: '8px', letterSpacing: '0.08em',
      cursor: 'pointer', padding: '6px 12px',
    },
  }

  return (
    <div style={S.overlay} onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div style={S.modal}>

        {/* HEADER */}
        <div style={S.header}>
          <div style={S.headerLeft}>
            <div style={S.title}>INVESTIGATION PLAYBOOK</div>
            <div style={S.subtitle}>
              {triage?.classification ?? 'Unknown'} · {triage?.mitre_id ?? '—'} · DETERMINISTIC
            </div>
          </div>
          <button style={S.closeBtn} onClick={onClose}>✕ CLOSE</button>
        </div>

        {/* BODY */}
        <div style={S.body}>

          {/* SIDEBAR */}
          <div style={S.sidebar}>
            {[
              { label: 'TARGET ASSET', value: triage?.affected_asset ?? 'Unknown' },
              { label: 'MITRE',        value: triage?.mitre_id ?? '—' },
              { label: 'SEVERITY',     value: triage?.severity ?? '—' },
              { label: 'VERDICT',      value: triage?.verdict_class ?? '—' },
              { label: 'IMPACT',       value: triage?.asset_is_critical ? 'HIGH — Critical Asset' : 'STANDARD' },
            ].map(({ label, value }) => (
              <div key={label} style={S.metaItem}>
                <div style={S.metaLabel}>{label}</div>
                <div style={S.metaValue}>{value}</div>
              </div>
            ))}

            <div style={S.divider} />

            <div style={S.metaItem}>
              <div style={S.metaLabel}>RELIABILITY</div>
              <div style={{ ...S.metaValue, color: isTraceRequired ? 'var(--amber)' : 'var(--green)' }}>
                {triage?.verdict_reliability_class ?? 'TRACE_REQUIRED'}
              </div>
            </div>

            {playbook?.meta?.dominant_signal && playbook.meta.dominant_signal !== 'unknown' && (
              <div style={S.metaItem}>
                <div style={S.metaLabel}>DOMINANT SIGNAL</div>
                <div style={{ ...S.metaValue, fontSize: '8px' }}>
                  {playbook.meta.dominant_signal}
                </div>
              </div>
            )}
          </div>

          {/* MAIN */}
          <div style={S.main}>

            {/* PHASE TABS */}
            <div style={S.phases}>
              {[
                { id: 'phase1', label: 'VERIFY VERDICT',            blocked: false },
                { id: 'phase2', label: 'SCOPE INCIDENT',            blocked: false },
                { id: 'phase3', label: 'CONTAINMENT PREREQUISITES', blocked: phase3Blocked },
              ].map(({ id, label, blocked }) => (
                <button
                  key={id}
                  style={S.phaseBtn(activePhase === id, blocked)}
                  onClick={() => setActivePhase(id)}
                >
                  {label}
                  {blocked && id === 'phase3' && (
                    <span style={{ marginLeft: '4px', color: 'var(--red)' }}>⊘</span>
                  )}
                </button>
              ))}
            </div>

            {/* CONTENT */}
            <div style={S.content}>
              {loading && (
                <div style={{
                  fontFamily: 'var(--font-mono), monospace',
                  fontSize: '9px', color: 'var(--text-muted)',
                  textAlign: 'center', padding: '40px',
                }}>
                  GENERATING PLAYBOOK...
                </div>
              )}

              {error && (
                <div style={{
                  fontFamily: 'var(--font-mono), monospace',
                  fontSize: '9px', color: 'var(--red)', padding: '16px',
                }}>
                  {error}
                </div>
              )}

              {playbook && !loading && (
                <>
                  {activePhase === 'phase1' && (
                    <div style={S.phaseNote}>{playbook.phase1.note}</div>
                  )}
                  {activePhase === 'phase2' && (
                    <div style={S.phaseNote}>{playbook.phase2.note}</div>
                  )}
                  {activePhase === 'phase3' && !phase3Blocked && (
                    <div style={S.phaseNote}>
                      These prerequisites must be established before any containment action.
                      No executable commands are generated — execution is your judgment, not the system's.
                    </div>
                  )}

                  {activePhase === 'phase3' && phase3Blocked && (
                    <div style={S.blockedBox}>
                      <div style={{
                        fontFamily: 'var(--font-mono), monospace',
                        fontSize: '8px', letterSpacing: '0.1em',
                        marginBottom: '8px', color: 'var(--red)',
                      }}>
                        ⊘ CONTAINMENT PREREQUISITES NOT GENERATED
                      </div>
                      {playbook.phase3.blocked_reason}
                    </div>
                  )}

                  {!(activePhase === 'phase3' && phase3Blocked) && (
                    <div style={S.stepsList}>
                      {getActiveSteps().map((step, i) => (
                        <div key={i} style={S.step}>
                          <div style={S.stepNum}>{String(i + 1).padStart(2, '0')}</div>
                          <div style={S.stepText}>{step}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>

        {/* FOOTER */}
        <div style={S.footer}>
          <span style={S.reliabilityBadge}>
            {isTraceRequired
              ? '⚠ TRACE_REQUIRED — validate before any action'
              : '✓ SURFACE_SAFE — proceed with Phase 1 verification'}
          </span>
          <button style={S.copyBtn} onClick={handleCopy}>
            {copied ? '✓ COPIED' : '⬡ COPY STEPS'}
          </button>
        </div>

      </div>
    </div>
  )
}
