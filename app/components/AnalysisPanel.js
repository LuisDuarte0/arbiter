'use client'
import React, { useState, useRef, useCallback } from 'react'
import ContainmentModal from './ContainmentModal'
import ThreatScanner from './ThreatScanner'

function Badge({ severity }) {
  return <span className={`arb-badge arb-${severity.toLowerCase()}`}>{severity}</span>
}

// Decision signal badges derived from triage data
function DecisionSignals({ triage, result }) {
  const signals = []

  if (result?.meta?.correlated)
    signals.push({ label: 'REDIS: REPEAT', color: '#E57373', bg: 'rgba(229,115,115,0.12)', icon: '↺' })
  if (result?.meta?.activeCampaign || result?.meta?.correlatedIndicatorActivity)
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
  rightCol: { padding: '12px 16px', display: 'flex', flexDirection: 'column', justifyContent: 'flex-start', alignItems: 'flex-start' },
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

function EnrichingLoader() {
  const canvasRef = React.useRef(null)
  React.useEffect(() => {
    const cv = canvasRef.current
    if (!cv) return
    const ctx = cv.getContext('2d')
    const sources = [
      { label: 'ABUSEIPDB', freq: 1.1 },
      { label: 'VIRUSTOTAL', freq: 0.8 },
      { label: 'OTX', freq: 1.4 },
    ]
    let t = 0, lastTs = null, rafId = null
    function frame(ts) {
      if (!cv.isConnected) return
      const dt = lastTs ? Math.min(ts - lastTs, 50) : 0
      lastTs = ts
      t += dt * 0.001
      const dpr = window.devicePixelRatio || 1
      const W = cv.width / dpr
      const H = cv.height / dpr
      ctx.clearRect(0, 0, cv.width, cv.height)
      ctx.save(); ctx.scale(dpr, dpr)
      const scanX = ((t * 0.4) % 1.4 - 0.2) * W
      sources.forEach((s, i) => {
        const y = 14 + i * 20
        const barStart = 90, barW = W - 110
        ctx.fillStyle = 'rgba(245,158,11,0.08)'
        ctx.fillRect(barStart, y, barW, 6)
        ctx.fillStyle = 'rgba(245,158,11,0.25)'
        ctx.font = '700 7px monospace'; ctx.textAlign = 'right'
        ctx.fillText(s.label, barStart - 8, y + 6)
        const dist = Math.abs(scanX - (y + 3))
        const lit = dist < 30
        if (lit) {
          const op = Math.max(0, 1 - dist / 30)
          ctx.fillStyle = `rgba(245,158,11,${op * 0.55})`
          ctx.fillRect(barStart, y, barW, 6)
          ctx.fillStyle = `rgba(245,158,11,${op * 0.9})`
          ctx.font = '700 7px monospace'; ctx.textAlign = 'right'
          ctx.fillText(s.label, barStart - 8, y + 6)
        }
      })
      for (let i = 0; i < 8; i++) {
        const bx = scanX - i * 6
        if (bx < 90 || bx > W - 20) continue
        ctx.fillStyle = `rgba(245,158,11,${(1 - i / 8) * 0.12})`
        ctx.fillRect(bx, 8, 4, 56)
      }
      if (scanX > 90 && scanX < W - 20) {
        ctx.fillStyle = 'rgba(245,158,11,0.7)'
        ctx.fillRect(scanX, 8, 1.5, 56)
      }
      ctx.fillStyle = 'rgba(245,158,11,0.25)'
      ctx.font = '6px monospace'; ctx.textAlign = 'center'
      ctx.fillText('QUERYING THREAT INTELLIGENCE', W / 2, H - 4)
      ctx.restore()
      rafId = requestAnimationFrame(frame)
    }
    const dpr = window.devicePixelRatio || 1
    cv.width = cv.offsetWidth * dpr
    cv.height = cv.offsetHeight * dpr
    rafId = requestAnimationFrame(frame)
    return () => { if (rafId) cancelAnimationFrame(rafId) }
  }, [])
  return (
    <canvas
      ref={canvasRef}
      style={{ display: 'block', width: '100%', height: '80px' }}
    />
  )
}

function AnalyzingLoader() {
  const canvasRef = React.useRef(null)
  React.useEffect(() => {
    const cv = canvasRef.current
    if (!cv) return
    const ctx = cv.getContext('2d')
    const stages = ['ACS', 'BEH', 'ENR', 'TMP', 'AGG']
    const colors = [
      'rgba(245,158,11,1)', 'rgba(245,158,11,0.8)',
      'rgba(239,68,68,0.9)', 'rgba(206,147,216,0.8)', 'rgba(245,158,11,1)'
    ]
    let t = 0, lastTs = null, rafId = null
    let particles = [], spawn = 0
    function frame(ts) {
      if (!cv.isConnected) return
      const dt = lastTs ? Math.min(ts - lastTs, 50) : 0
      lastTs = ts
      t += dt * 0.001
      spawn += dt
      const dpr = window.devicePixelRatio || 1
      const W = cv.width / dpr
      const H = cv.height / dpr
      const segW = Math.min(48, (W - 80) / stages.length - 8)
      const gap = 10
      const totalW = stages.length * segW + (stages.length - 1) * gap
      const startX = (W - totalW) / 2
      if (spawn > 500) {
        spawn = 0
        particles.push({ x: startX - 10, p: 0, speed: 0.0005 + Math.random() * 0.0003 })
      }
      particles = particles.filter(p => p.p < 1)
      ctx.clearRect(0, 0, cv.width, cv.height)
      ctx.save(); ctx.scale(dpr, dpr)
      stages.forEach((s, i) => {
        const x = startX + i * (segW + gap)
        ctx.strokeStyle = 'rgba(245,158,11,0.10)'; ctx.lineWidth = 0.5
        ctx.strokeRect(x, 18, segW, 28)
        ctx.fillStyle = 'rgba(245,158,11,0.12)'; ctx.font = '7px monospace'; ctx.textAlign = 'center'
        ctx.fillText(s, x + segW / 2, 34)
        if (i < stages.length - 1) {
          ctx.strokeStyle = 'rgba(245,158,11,0.08)'; ctx.lineWidth = 0.5
          ctx.beginPath(); ctx.moveTo(x + segW, 32); ctx.lineTo(x + segW + gap, 32); ctx.stroke()
        }
      })
      particles.forEach(p => {
        p.p += dt * p.speed
        const x = startX - 10 + (totalW + 30) * p.p
        const stageI = Math.floor((x - startX) / (segW + gap))
        const col = stageI >= 0 && stageI < stages.length ? colors[stageI] : 'rgba(245,158,11,1)'
        if (stageI >= 0 && stageI < stages.length) {
          const sx = startX + stageI * (segW + gap)
          ctx.fillStyle = col.replace(/[\d.]+\)$/, '0.08)')
          ctx.fillRect(sx, 18, segW, 28)
          ctx.strokeStyle = col.replace(/[\d.]+\)$/, '0.5)')
          ctx.lineWidth = 1; ctx.strokeRect(sx, 18, segW, 28)
          ctx.fillStyle = col.replace(/[\d.]+\)$/, '0.8)')
          ctx.font = '700 7px monospace'; ctx.textAlign = 'center'
          ctx.fillText(stages[stageI], sx + segW / 2, 34)
        }
        for (let i = 1; i < 5; i++) {
          ctx.fillStyle = `rgba(245,158,11,${(1 - i / 5) * 0.3})`
          ctx.beginPath(); ctx.arc(x - i * 8, 32, 1.5, 0, Math.PI * 2); ctx.fill()
        }
        ctx.fillStyle = '#F59E0B'
        ctx.beginPath(); ctx.arc(x, 32, 3, 0, Math.PI * 2); ctx.fill()
      })
      ctx.fillStyle = 'rgba(245,158,11,0.25)'
      ctx.font = '6px monospace'; ctx.textAlign = 'center'
      ctx.fillText('EVALUATING BEHAVIORAL SIGNALS', W / 2, H - 4)
      ctx.restore()
      rafId = requestAnimationFrame(frame)
    }
    const dpr = window.devicePixelRatio || 1
    cv.width = cv.offsetWidth * dpr
    cv.height = cv.offsetHeight * dpr
    rafId = requestAnimationFrame(frame)
    return () => { if (rafId) cancelAnimationFrame(rafId) }
  }, [])
  return (
    <canvas
      ref={canvasRef}
      style={{ display: 'block', width: '100%', height: '80px' }}
    />
  )
}

export default function AnalysisPanel({ alertText, setAlertText, result, loading, loadingPhase, error, onTriage, onReset }) {
  const [containmentOpen, setContainmentOpen] = useState(false)

  const effectiveResult = result
  const triage        = effectiveResult?.triage ?? null
  const decisionTrace = (() => {
    const raw = effectiveResult?.meta?.decisionTrace ?? effectiveResult?.meta?.deterministicOverrides ?? []
    return raw.filter(e => typeof e === 'object' && e.type)
  })()
  const signals       = effectiveResult?.meta?.signals ?? []

  // ── Threat Scanner state ─────────────────────────────────────────────────
  // Scanner is active when the field is empty and the user has not yet
  // focused or interacted with it. Once dismissed, it restarts only after
  // the field is empty AND focus has left the textarea for 1.5 s.
  const [scannerDismissed, setScannerDismissed] = useState(false)
  const restartTimerRef = useRef(null)
  const scannerActive = alertText.trim() === '' && !scannerDismissed

  const handleTextareaFocus = useCallback(() => {
    if (restartTimerRef.current) clearTimeout(restartTimerRef.current)
    setScannerDismissed(true)
  }, [])

  const handleTextareaBlur = useCallback(() => {
    if (alertText.trim() === '') {
      restartTimerRef.current = setTimeout(() => setScannerDismissed(false), 1500)
    }
  }, [alertText])

  const isUrgent = triage?.severity === 'CRITICAL' || triage?.severity === 'HIGH'

  const verdictClass = triage?.verdict_class
    ?? effectiveResult?.meta?.verdictClass
    ?? 'DEFENSIBLE_VERDICT'

  const verdictReliabilityClass = triage?.verdict_reliability_class
    ?? effectiveResult?.meta?.verdictReliabilityClass
    ?? 'TRACE_REQUIRED'

  const isIBE = verdictClass === 'NO_DETECTION'
             || verdictClass === 'INSUFFICIENT_DATA'

  const isEnrichmentOnly = verdictClass === 'ENRICHMENT_ONLY_VERDICT'

  const isLowConfidence = verdictClass === 'LOW_CONFIDENCE_VERDICT'

  const displayConfidence = triage?.behavioral_confidence ?? triage?.confidence ?? 0
  const qualityFactor = triage?.quality_factor ?? effectiveResult?.meta?.quality_factor ?? 'UNKNOWN'
  const qfColors = {
    HIGH:    { color: 'var(--green)',      label: 'DATA: HIGH' },
    MEDIUM:  { color: 'var(--amber)',      label: 'DATA: MED'  },
    LOW:     { color: 'var(--red)',        label: 'DATA: LOW'  },
    UNKNOWN: { color: 'var(--text-muted)', label: 'DATA: ?'    },
  }
  const qf = qfColors[qualityFactor] ?? qfColors.UNKNOWN

  const isSurfaceSafe = verdictReliabilityClass === 'SURFACE_SAFE'

  const vendorOrigin = effectiveResult?.meta?.vendor_origin ?? 'unknown'

  const vendorDisplayName = {
    windows:    'Windows Event Log',
    linux:      'System Auth Log',
    cloudtrail: 'AWS CloudTrail',
    generic:    'Unknown Log Source',
    unknown:    'Unknown Log Source',
  }[vendorOrigin] ?? 'Unknown Log Source'

  const vendorPlaybookLabel = {
    windows:    'PowerShell · CMD · Investigation · Warnings',
    linux:      'Bash · Journalctl · Investigation · Warnings',
    cloudtrail: 'AWS CLI · IAM · Investigation · Warnings',
    generic:    'Investigation · Warnings',
    unknown:    'Investigation · Warnings',
  }[vendorOrigin] ?? 'Investigation · Warnings'


  return (
    <div className="arb-panel arb-analysis">

      {/* INPUT BLOCK — hidden when result is present */}
      {!result && <div className="arb-input-block">
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
        <div className="arb-textarea-wrapper">
          <ThreatScanner active={scannerActive} />
          <textarea
            className={`arb-textarea${scannerActive ? ' scanner-idle' : ''}`}
            value={alertText}
            onChange={e => setAlertText(e.target.value)}
            onFocus={handleTextareaFocus}
            onBlur={handleTextareaBlur}
            style={{ minHeight: result || loading ? '140px' : '110px' }}
            placeholder={`EventCode=4625 LogonType=3\nTargetUserName=admin\nIpAddress=185.220.101.47\nFailureReason=%%2313\n\n— paste your alert here —`}
            spellCheck={false}
          />
        </div>
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
      </div>}

      {/* LOADING */}
      {loading && (
        <div style={{ padding: '16px 22px', borderBottom: '0.5px solid var(--border)' }}>
          <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'rgba(245,158,11,0.5)', letterSpacing: '0.15em', marginBottom: '10px' }}>
            {loadingPhase === 'enriching' ? 'ENRICHING THREAT INTELLIGENCE' : 'ARBITER IS ANALYZING YOUR ALERT'}
          </div>
          {loadingPhase === 'enriching' ? <EnrichingLoader /> : <AnalyzingLoader />}
        </div>
      )}

      {/* EMPTY STATE */}
      {!result && !loading && (
        <div style={{ padding: '16px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px', opacity: 0.75 }}>
          <svg viewBox="-8 0 136 120" width="28" height="25" xmlns="http://www.w3.org/2000/svg">
            <line x1="60" y1="8" x2="6" y2="112" stroke="rgba(255,255,255,0.20)" strokeWidth="17" strokeLinecap="square"/>
            <line x1="60" y1="8" x2="114" y2="112" stroke="rgba(255,255,255,0.20)" strokeWidth="17" strokeLinecap="square"/>
            <line x1="-6" y1="68" x2="126" y2="68" stroke="rgba(255,255,255,0.20)" strokeWidth="7" strokeLinecap="square"/>
          </svg>
          <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'rgba(255,255,255,0.35)', letterSpacing: '0.18em', textAlign: 'center', lineHeight: '1.8' }}>
            READY FOR TRIAGE<br/><span style={{ fontSize: '8px', color: 'rgba(255,255,255,0.35)', letterSpacing: '0.18em' }}>PASTE AN ALERT AND CLICK ANALYZE</span>
          </div>
        </div>
      )}

      {/* IBE STATE — no behavioral indicators */}
      {triage && isIBE && (
        <div>
          {/* VERDICT HERO — IBE STATE */}
          <div style={{ ...S.verdictHero, borderLeft: '3px solid var(--red)' }}>
            <div style={S.verdictLeft}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Badge severity={triage.severity} />
                <span style={{
                  fontFamily: 'var(--font-mono), monospace',
                  fontSize: '8px',
                  letterSpacing: '0.1em',
                  color: 'var(--red)',
                  background: 'var(--red-15)',
                  border: '0.5px solid var(--red-40)',
                  borderRadius: '3px',
                  padding: '2px 8px',
                }}>
                  {verdictClass === 'INSUFFICIENT_DATA'
                    ? 'INSUFFICIENT DATA'
                    : 'NO DETECTION'}
                </span>
              </div>
              <div style={{ ...S.verdictTitle, color: 'var(--text-secondary)', fontSize: '18px', marginTop: '6px' }}>
                {verdictClass === 'INSUFFICIENT_DATA'
                  ? 'Log format could not be normalized to behavioral primitives'
                  : 'No signals of any kind could be derived from this log'}
              </div>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '6px', lineHeight: '1.6' }}>
                {verdictClass === 'INSUFFICIENT_DATA'
                  ? 'The ACS normalization layer could not extract sufficient independent fields from this log. Review the raw input and verify the correct mapper applies.'
                  : (() => {
                      const hasEnrichment = result?.meta?.enrichmentSources?.length > 0
                        || result?.enrichment?.judgment === 'CONFIRMED_MALICIOUS'
                        || result?.enrichment?.judgment === 'SUSPICIOUS'
                      return hasEnrichment
                        ? "No behavioral signals could be derived from this log format. External threat intelligence is available in the Intel panel — the source IP has been evaluated against external databases. Review the raw log manually for structural context."
                        : "Neither behavioral primitives nor domain-specific detection signals could be derived from the normalized data. No defensible verdict can be issued. Review the raw log manually."
                    })()}
              </div>
            </div>
            <div style={S.verdictRight}>
              <div style={S.confBlock}>
                <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '32px', fontWeight: '600', color: 'var(--text-muted)', lineHeight: '1' }}>—</div>
                <div style={S.confLabel}>NO VERDICT</div>
              </div>
            </div>
          </div>

          {/* EXTRACTED FIELDS — show what was parsed */}
          {triage.evidence?.length > 0 && (
            <div style={{ padding: '12px 22px', borderBottom: '0.5px solid var(--border)' }}>
              <div style={S.sectionLabel}>EXTRACTED FIELDS</div>
              <div style={S.evidenceChips}>
                {triage.evidence.map((item, i) => {
                  const eqIdx = item.indexOf('=')
                  const field = eqIdx > -1 ? item.slice(0, eqIdx) : item
                  const val = eqIdx > -1 ? item.slice(eqIdx + 1) : ''
                  return (
                    <div key={i} style={{ ...S.chip, color: 'var(--text-muted)', background: 'transparent', border: '0.5px solid var(--border-bright)' }}>
                      <span>{field}</span>
                      {val && <><span style={{ color: 'var(--border-bright)' }}>=</span><span style={{ color: 'var(--text-secondary)', fontSize: '8px' }}>{val.length > 20 ? val.slice(0, 20) + '…' : val}</span></>}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* NO RECOMMENDATIONS — explain why */}
          <div style={{ padding: '16px 22px', background: 'rgba(239,68,68,0.03)', borderBottom: '0.5px solid var(--border)' }}>
            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--red)', letterSpacing: '0.15em', marginBottom: '6px' }}>NO INVESTIGATION PATH GENERATED</div>
            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '10px', color: 'var(--text-muted)', lineHeight: '1.6' }}>
              Investigation hypotheses require at least one defensible behavioral signal. No recommendations are generated when no behavioral evidence exists — generating them would be fabrication.
            </div>
          </div>
        </div>
      )}

      {triage && isEnrichmentOnly && (
        <div>
          {/* VERDICT HERO — enrichment only state */}
          <div style={{ ...S.verdictHero, borderLeft: '3px solid var(--amber)' }}>
            <div style={S.verdictLeft}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Badge severity={triage.severity} />
                <span style={{
                  fontFamily: 'var(--font-mono), monospace',
                  fontSize: '8px',
                  letterSpacing: '0.1em',
                  color: 'var(--amber)',
                  background: 'var(--amber-15)',
                  border: '0.5px solid var(--amber-40)',
                  borderRadius: '3px',
                  padding: '2px 8px',
                }}>ENRICHMENT-BASED VERDICT</span>
              </div>
              <div style={S.verdictTitle}>{triage.classification}</div>
              <div style={S.verdictSub}>
                <span>{triage.tactic}</span>
                <span style={{ color: 'var(--border-bright)' }}>·</span>
                <span style={{ color: 'var(--amber)' }}>{triage.mitre_id}</span>
                <span style={{ color: 'var(--border-bright)' }}>·</span>
                <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--amber)', letterSpacing: '0.06em' }}>TRACE_REQUIRED</span>
              </div>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-muted)', marginTop: '6px', lineHeight: '1.6', maxWidth: '380px' }}>
                Detected via domain-specific knowledge (EventID semantics, asset rules). No vendor-agnostic behavioral primitives were derived. Verdict is reliable within its vendor context but requires trace validation before acting.
              </div>
            </div>
            <div style={S.verdictRight}>
              <div style={S.confBlock}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px' }}>
                  <span style={S.confBig}>{displayConfidence}</span>
                  <span style={S.confUnit}>%</span>
                </div>
                <div style={S.confLabel}>BEHAVIORAL CONFIDENCE</div>
                <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: qf.color, letterSpacing: '0.06em', marginTop: '3px', textAlign: 'right' }}>
                  {qf.label}
                </div>
                <div style={S.confBarWrap}>
                  <div style={{ height: '100%', background: 'var(--amber)', borderRadius: '1px', width: `${displayConfidence}%`, opacity: '0.6' }} />
                </div>
              </div>
            </div>
          </div>

          {/* DECISION SIGNALS */}
          <DecisionSignals triage={triage} result={result} />

          {/* TWO COLUMN — MITRE + ASSET left, EVIDENCE right */}
          <div style={S.twoCol}>
            <div style={S.leftCol}>
              <div style={S.metaBlock}>
                <div style={S.sectionLabel}>MITRE ATT&CK</div>
                <div style={S.metaId}>{triage.mitre_id}</div>
                <div style={S.metaName}>{triage.mitre_name}</div>
                <div style={S.metaDetail}>{triage.mitre_tactic} · {vendorDisplayName}</div>
              </div>
              <div style={S.divider} />
              <div style={S.metaBlock}>
                <div style={S.sectionLabel}>AFFECTED ASSET</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ ...S.assetName, color: triage.asset_is_critical ? '#F59E0B' : 'var(--text-primary)' }}>
                    {triage.affected_asset}
                  </div>
                </div>
                <span style={{
                  fontFamily: 'var(--font-mono), monospace', fontSize: '7px',
                  color: triage.asset_is_critical ? '#E57373' : 'var(--text-muted)',
                  background: triage.asset_is_critical ? 'rgba(229,115,115,0.12)' : 'rgba(255,255,255,0.04)',
                  border: `0.5px solid ${triage.asset_is_critical ? 'rgba(229,115,115,0.4)' : 'rgba(255,255,255,0.08)'}`,
                  borderRadius: '2px', padding: '2px 6px', marginTop: '5px', display: 'inline-block',
                }}>
                  {triage.asset_is_critical ? '⚠ CRITICAL ASSET' : 'STANDARD ASSET'}
                </span>
              </div>
            </div>
            <div style={{ ...S.rightCol, justifyContent: 'flex-start', alignItems: 'flex-start' }}>
              <div style={S.sectionLabel}>EVIDENCE</div>
              <div style={S.evidenceChips}>
                {(triage.evidence ?? []).map((item, i) => {
                  const eqIdx = item.indexOf('=')
                  const field = eqIdx > -1 ? item.slice(0, eqIdx) : item
                  const val = eqIdx > -1 ? item.slice(eqIdx + 1) : ''
                  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(val) || field.toLowerCase().includes('ip')
                  const isUser = field.toLowerCase().includes('user')
                  const chipColor = isIP ? '#64B5F6' : isUser ? '#CE93D8' : 'var(--amber)'
                  const chipBg = isIP ? 'rgba(100,181,246,0.1)' : isUser ? 'rgba(206,147,216,0.1)' : 'var(--amber-15)'
                  const chipBorder = isIP ? 'rgba(100,181,246,0.3)' : isUser ? 'rgba(206,147,216,0.3)' : 'var(--amber-40)'
                  return (
                    <div key={i} style={{ ...S.chip, color: chipColor, background: chipBg, border: `0.5px solid ${chipBorder}` }}>
                      <span>{field}</span>
                      {val && <><span style={{ color: `${chipColor}50` }}>=</span><span style={{ color: 'var(--text-primary)', fontSize: '8px' }}>{val.length > 20 ? val.slice(0, 20) + '…' : val}</span></>}
                    </div>
                  )
                })}
              </div>
            </div>
          </div>

          {/* ENGINE DECISION TRACE */}
          {decisionTrace.length > 0 && (
            <div style={{ ...S.reasoningSection, marginBottom: 0, paddingBottom: '14px', borderBottom: '0.5px solid var(--border)', borderTop: '0.5px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={S.sectionLabel}>ENGINE DECISION TRACE</div>
                <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
                  {(result?.meta?.signals ?? []).length} SIGNAL{(result?.meta?.signals ?? []).length !== 1 ? 'S' : ''} · ENRICHMENT-BASED · {result?.meta?.parseQuality?.toUpperCase() ?? 'UNKNOWN'} PARSE
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
                      <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color, letterSpacing: '0.1em', minWidth: '80px', paddingTop: '1px', textTransform: 'uppercase', opacity: 0.8 }}>{e.type}</span>
                      <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: e.type === 'dominant' ? '10px' : '9px', color: e.type === 'dominant' ? 'var(--amber)' : 'var(--text-secondary)', lineHeight: '1.5', flex: 1 }}>
                        {e.label}
                        {e.rule && <span style={{ color: 'var(--text-muted)', fontSize: '8px' }}> [{e.rule}]</span>}
                      </span>
                      {e.severity && <span className={`arb-badge arb-${e.severity?.toLowerCase()}`} style={{ fontSize: '7px', flexShrink: 0 }}>{e.severity}</span>}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* RECOMMENDED ACTIONS */}
          {triage.recommendations?.length > 0 && (
            <div style={{ padding: '14px 22px', borderBottom: '0.5px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <div style={S.actionsLabel}>RECOMMENDED ACTIONS</div>
                <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--amber)', letterSpacing: '0.08em' }}>ENRICHMENT-DERIVED</span>
              </div>
              <div style={S.stepsList}>
                {triage.recommendations.map((rec, i) => {
                  const signalRule = triage.recommendation_provenance?.[i]
                  return (
                    <div key={i} style={{ ...S.step, position: 'relative' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                        <div style={S.stepNum}>{String(i + 1).padStart(2, '0')}</div>
                        {i < triage.recommendations.length - 1 && <div style={{ width: '0.5px', flex: '1', minHeight: '6px', background: 'var(--border-bright)', margin: '2px 0' }} />}
                      </div>
                      <div style={{ flex: 1, paddingBottom: i === triage.recommendations.length - 1 ? 0 : '8px' }}>
                        <div style={S.stepText}>{rec}</div>
                        {signalRule && <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginTop: '2px' }}>↳ {signalRule}</div>}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* BEHAVIORAL SYNTHESIS */}
          {triage.reasoning && (
            <div style={{ padding: '14px 22px', borderBottom: '0.5px solid var(--border)', background: 'rgba(100,181,246,0.02)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.18em', color: '#64B5F6', textTransform: 'uppercase' }}>BEHAVIORAL SYNTHESIS</div>
                  <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'rgba(100,181,246,0.6)', background: 'rgba(100,181,246,0.08)', border: '0.5px solid rgba(100,181,246,0.2)', borderRadius: '2px', padding: '1px 6px', letterSpacing: '0.06em' }}>LLM-GENERATED</span>
                </div>
                <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.06em' }}>not in forensic export</span>
              </div>
              <div style={{ background: 'rgba(100,181,246,0.04)', borderLeft: '2px solid rgba(100,181,246,0.4)', borderRadius: '0 4px 4px 0', padding: '12px 16px' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.8' }}>
                  {typeof triage.reasoning === 'string' ? triage.reasoning : Array.isArray(triage.reasoning) ? triage.reasoning.join(' ') : triage.reasoning?.text ?? ''}
                </div>
              </div>
            </div>
          )}

          {/* CONTAINMENT CTA */}
          <div style={S.containmentSection}>
            <div style={S.containmentLeft}>
              <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--amber)', letterSpacing: '0.08em' }}>
                ⚠ TRACE_REQUIRED — validate reasoning before acting
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
              {result && (
                <button onClick={() => {
                  // reasoning excluded — LLM synthesis is not evidence
                  const forensic = {
                    case_id: result?.meta?.alertType ?? 'UNKNOWN',
                    timestamp: new Date().toISOString(),
                    severity: triage.severity,
                    classification: triage.classification,
                    behavioral_confidence: triage.behavioral_confidence ?? triage.confidence,
                    quality_factor: triage.quality_factor ?? result?.meta?.quality_factor ?? 'UNKNOWN',
                    mitre_id: triage.mitre_id,
                    mitre_name: triage.mitre_name,
                    tactic: triage.tactic,
                    mitre_tactic: triage.mitre_tactic,
                    affected_asset: triage.affected_asset,
                    asset_is_critical: triage.asset_is_critical,
                    evidence: triage.evidence,
                    signals: result?.meta?.signals ?? [],
                    decision_trace: result?.meta?.deterministicOverrides ?? [],
                    recommendations: triage.recommendations,
                    enrichment_sources: result?.meta?.enrichmentSources ?? [],
                    correlated: result?.meta?.correlated ?? false,
                    parse_quality: result?.meta?.parseQuality ?? 'unknown',
                    verdict_class: triage.verdict_class ?? 'ENRICHMENT_ONLY_VERDICT',
                    verdict_reliability_class: triage.verdict_reliability_class ?? 'TRACE_REQUIRED',
                  }
                  navigator.clipboard.writeText(JSON.stringify(forensic, null, 2))
                }}
                style={{ background: 'none', border: '0.5px solid var(--border-bright)', borderRadius: '3px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.08em', cursor: 'pointer', padding: '6px 10px', whiteSpace: 'nowrap' }}
                onMouseEnter={e => { e.currentTarget.style.color = 'var(--text-secondary)' }}
                onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)' }}>
                  ⬡ FORENSIC
                </button>
              )}
              <button style={{ display: 'flex', alignItems: 'center', gap: '10px', background: isUrgent ? 'var(--red)' : 'var(--amber)', border: 'none', borderRadius: '4px', padding: '9px 18px', cursor: 'pointer', flexShrink: 0 }}
                onClick={() => setContainmentOpen(true)}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#080C14" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" />
                </svg>
                <span style={S.containmentBtnLabel}>GENERATE CONTAINMENT PLAYBOOK</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* NORMAL TRIAGE RENDER — only when behavioral evidence exists */}
      {triage && !isIBE && !isEnrichmentOnly && (
        <div>

          {/* 1. VERDICT HERO */}
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
                {verdictReliabilityClass && (
                  <>
                    <span style={{ color: 'var(--border-bright)' }}>·</span>
                    <span style={{
                      fontFamily: 'var(--font-mono), monospace',
                      fontSize: '8px',
                      color: isSurfaceSafe ? 'var(--green)' : 'var(--amber)',
                      letterSpacing: '0.06em',
                      fontWeight: isSurfaceSafe ? '600' : '400',
                    }}>
                      {isSurfaceSafe ? 'SURFACE_SAFE' : 'TRACE_REQUIRED'}
                    </span>
                  </>
                )}
              </div>
            </div>
            <div style={S.verdictRight}>
              <div style={S.confBlock}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px' }}>
                  <span style={S.confBig}>{displayConfidence}</span>
                  <span style={S.confUnit}>%</span>
                </div>
                <div style={S.confLabel}>BEHAVIORAL CONFIDENCE</div>
                <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: qf.color, letterSpacing: '0.06em', marginTop: '3px', textAlign: 'right' }}>
                  {qf.label}
                </div>
                <div style={S.confBarWrap}>
                  <div style={{ height: '100%', background: 'var(--amber)', borderRadius: '1px', width: `${displayConfidence}%` }} />
                </div>
                {(() => {
                  const ct = decisionTrace.find(e => e.type === 'confidence')
                  if (!ct) return null
                  return (
                    <div style={{ marginTop: '6px', display: 'flex', flexDirection: 'column', gap: '2px' }}>
                      {ct.dominantConf     != null && <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>DOMINANT <span style={{ color: 'var(--text-secondary)' }}>{ct.dominantConf}%</span></div>}
                      {ct.supportingContrib != null && ct.supportingContrib > 0 && <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>SUPPORTING <span style={{ color: 'var(--text-secondary)' }}>+{ct.supportingContrib}%</span></div>}
                      {ct.temporalBoost    != null && ct.temporalBoost > 0 && <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>TEMPORAL <span style={{ color: '#64B5F6' }}>+{ct.temporalBoost}%</span></div>}
                      {ct.enrichmentAlignment != null && ct.enrichmentAlignment > 0 && <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>ENRICHMENT ALIGN <span style={{ color: 'var(--green)' }}>+{ct.enrichmentAlignment}%</span></div>}
                    </div>
                  )
                })()}
              </div>
            </div>
          </div>

          {/* 2. DECISION SIGNALS */}
          <DecisionSignals triage={triage} result={result} />

          {/* 3. TWO-COLUMN BODY — LEFT: MITRE + ASSET | RIGHT: EVIDENCE */}
          <div style={S.twoCol}>

            {/* LEFT — MITRE ATT&CK + AFFECTED ASSET */}
            <div style={S.leftCol}>
              <div style={S.metaBlock}>
                <div style={S.sectionLabel}>MITRE ATT&CK</div>
                <div style={S.metaId}>{triage.mitre_id}</div>
                <div style={S.metaName}>{triage.mitre_name}</div>
                <div style={S.metaDetail}>{triage.mitre_tactic} · {vendorDisplayName}</div>
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
            </div>

            {/* RIGHT — EVIDENCE */}
            <div style={{ ...S.rightCol, justifyContent: 'flex-start', alignItems: 'flex-start' }}>
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
          </div>

          {/* 4. LOW_CONFIDENCE BANNER + ENGINE DECISION TRACE */}
          {isLowConfidence && (
            <div style={{ padding: '6px 22px', background: 'rgba(245,158,11,0.06)', borderBottom: '0.5px solid var(--amber-40)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--amber)', letterSpacing: '0.1em' }}>⚠ LOW_CONFIDENCE_VERDICT</span>
              <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)' }}>behavioral signal exists but normalization quality or signal weight is insufficient for high confidence — validate trace before acting</span>
            </div>
          )}

          {decisionTrace.length > 0 && (
            <div style={{ ...S.reasoningSection, marginBottom: 0, paddingBottom: '14px', borderBottom: '0.5px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={S.sectionLabel}>ENGINE DECISION TRACE</div>
                <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
                  {(result?.meta?.signals ?? []).length} SIGNAL{(result?.meta?.signals ?? []).length !== 1 ? 'S' : ''} · {result?.meta?.parseQuality?.toUpperCase() ?? 'UNKNOWN'} PARSE · DETERMINISTIC
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
                        {e.type === 'penalty' ? e.label.replace(/\s*[+-]?\d+\s*$/, '') : e.label}
                        {e.rule && <span style={{ color: 'var(--text-muted)', fontSize: '8px', fontWeight: '400' }}> [{e.rule}]</span>}
                        {e.type === 'confidence' && e.dominantConf !== undefined && (
                          <span style={{ color: 'var(--text-muted)', fontSize: '8px' }}> (dominant={e.dominantConf}%, temporal=+{e.temporalBoost ?? 0}%)</span>
                        )}
                      </span>
                      {e.severity && <span className={`arb-badge arb-${e.severity?.toLowerCase()}`} style={{ fontSize: '7px', flexShrink: 0 }}>{e.severity}</span>}
                      {e.type === 'penalty' && e.value !== undefined && <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--red)', flexShrink: 0 }}>{e.value > 0 ? `+${e.value}` : e.value}</span>}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* 5. RECOMMENDED ACTIONS — full width, signal-rule provenance */}
          <div style={{ padding: '14px 22px', borderBottom: '0.5px solid var(--border)', borderTop: '0.5px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
              <div style={S.actionsLabel}>RECOMMENDED ACTIONS</div>
              <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>DETERMINISTIC · SIGNAL-DERIVED</span>
            </div>
            <div style={S.stepsList}>
              {(triage.recommendations ?? []).map((rec, i) => {
                const signalRule = triage.recommendation_provenance?.[i]
                return (
                  <div key={i} style={{ ...S.step, position: 'relative' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                      <div style={S.stepNum}>{String(i + 1).padStart(2, '0')}</div>
                      {i < triage.recommendations.length - 1 && (
                        <div style={{ width: '0.5px', flex: '1', minHeight: '6px', background: 'var(--border-bright)', margin: '2px 0' }} />
                      )}
                    </div>
                    <div style={{ flex: 1, paddingBottom: i === triage.recommendations.length - 1 ? 0 : '8px' }}>
                      <div style={S.stepText}>{rec}</div>
                      {signalRule && (
                        <div style={{ fontFamily: 'var(--font-mono),monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginTop: '2px' }}>
                          ↳ {signalRule}
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
              {(!triage.recommendations || triage.recommendations.length === 0) && (
                <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
                  No behavioral signals generated investigation hypotheses for this alert.
                </div>
              )}
            </div>
          </div>

          {/* 6. BEHAVIORAL SYNTHESIS — LLM layer, explicit epistemic marker */}
          <div style={{ padding: '14px 22px', borderBottom: '0.5px solid var(--border)', background: 'rgba(100,181,246,0.02)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.18em', color: '#64B5F6', textTransform: 'uppercase' }}>
                  BEHAVIORAL SYNTHESIS
                </div>
                <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'rgba(100,181,246,0.6)', background: 'rgba(100,181,246,0.08)', border: '0.5px solid rgba(100,181,246,0.2)', borderRadius: '2px', padding: '1px 6px', letterSpacing: '0.06em' }}>
                  LLM-GENERATED
                </span>
              </div>
              <span style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '7px', color: 'var(--text-muted)', letterSpacing: '0.06em' }}>
                not in forensic export
              </span>
            </div>

            <div style={{ background: 'rgba(100,181,246,0.04)', borderLeft: '2px solid rgba(100,181,246,0.4)', borderRadius: '0 4px 4px 0', padding: '12px 16px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.8' }}>
                {triage.reasoning
                  ? (typeof triage.reasoning === 'string'
                      ? triage.reasoning
                      : Array.isArray(triage.reasoning)
                        ? triage.reasoning.join(' ')
                        : triage.reasoning?.text ?? '')
                  : <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono), monospace', fontSize: '10px' }}>No synthesis available — deterministic verdict stands alone.</span>
                }
              </div>
            </div>

            <div style={{ fontFamily: 'var(--font-mono), monospace', fontSize: '8px', color: 'var(--text-muted)', letterSpacing: '0.04em', marginTop: '8px', lineHeight: '1.5' }}>
              This synthesis is pattern-based interpretation generated by a language model. It represents a plausible reading of the combined signals — not a verified conclusion. The ENGINE DECISION TRACE above this section is the authoritative ground truth.
            </div>
          </div>

          {/* 7. CONTAINMENT CTA */}
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
                {vendorPlaybookLabel}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
              {result && (
                <button
                  onClick={() => {
                    // reasoning excluded — LLM synthesis is not evidence
                    const forensic = {
                      case_id: result?.meta?.alertType ?? 'UNKNOWN',
                      timestamp: new Date().toISOString(),
                      severity: triage.severity,
                      classification: triage.classification,
                      behavioral_confidence: triage.behavioral_confidence ?? triage.confidence,
                      quality_factor: triage.quality_factor ?? result?.meta?.quality_factor ?? 'UNKNOWN',
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
                      verdict_class: result?.triage?.verdict_class ?? result?.meta?.verdictClass ?? 'UNKNOWN',
                      verdict_reliability_class: result?.triage?.verdict_reliability_class ?? result?.meta?.verdictReliabilityClass ?? 'UNKNOWN',
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
