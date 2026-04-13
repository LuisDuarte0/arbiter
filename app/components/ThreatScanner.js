'use client'
import { useEffect, useRef } from 'react'

// Fragment vocabulary — cycles randomly each sweep
const VOCAB = [
  'EventCode=4625 · LogonType=3 · IpAddress=185.220.101.47',
  'TargetUserName=admin · FailureReason=%%2313',
  'ACS_AUTH_FAILURE_HIGH · T1110 · BRUTE_FORCE',
  '{"eventName":"AttachUserPolicy","errorCode":null}',
  'action=attachuserpolicy · user=analyst · event_outcome=success',
  'Apr 10 09:17:14 prod-server sshd[12891]: Failed password',
  'CORRELATED_INDICATOR_ACTIVITY · CRITICAL · 3 SIGNALS',
  'vendor_origin=cloudtrail · normalization_score=0.82',
]

const SWEEP_MS   = 3500  // one full top→bottom pass
const FADE_DUR   = 300   // ms for opacity fade in/out
const FADE_IN_PX = 22    // px before scan reaches fragment
const FADE_OUT_PX= 30    // px after scan passes fragment
const PEAK_OP    = 0.50  // fragment peak opacity

export default function ThreatScanner({ active }) {
  const canvasRef  = useRef(null)
  // All mutable animation state lives in a ref to avoid triggering re-renders
  const stateRef   = useRef({
    scanY:         0,
    scanOpacity:   0,
    targetOpacity: 0,
    slots:         [],
    rafId:         null,
    lastTs:        null,
    W:             1,
    H:             1,
  })

  // ── One-time canvas setup and animation loop ────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx   = canvas.getContext('2d')
    const state = stateRef.current

    function buildSlots() {
      const { W, H } = state
      const count  = 11
      const zoneH  = H / count
      const used   = new Set()
      state.slots  = []
      for (let i = 0; i < count; i++) {
        let fi, tries = 0
        do { fi = Math.floor(Math.random() * VOCAB.length); tries++ }
        while (used.has(fi) && tries < 20)
        used.add(fi)
        const text = VOCAB[fi]
        const textW = text.length * 6.5  // approx mono char width at 11px
        const maxX  = Math.max(16, W - textW - 16)
        state.slots.push({
          text,
          y: (i + 0.5) * zoneH,
          x: 16 + Math.random() * maxX,
        })
      }
    }

    function resize() {
      const rect = canvas.getBoundingClientRect()
      if (rect.width === 0 || rect.height === 0) return
      const dpr = window.devicePixelRatio || 1
      state.W = rect.width
      state.H = rect.height
      canvas.width  = Math.round(state.W * dpr)
      canvas.height = Math.round(state.H * dpr)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      buildSlots()
    }


    function drawScanLine(sy, op) {
      const { W } = state
      ctx.save()

      // Gradient trail above the scan line
      const trailH = Math.min(55, sy)
      if (trailH > 1) {
        const grad = ctx.createLinearGradient(0, sy - trailH, 0, sy)
        grad.addColorStop(0, 'rgba(245,158,11,0)')
        grad.addColorStop(1, `rgba(245,158,11,${0.08 * op})`)
        ctx.fillStyle = grad
        ctx.fillRect(0, sy - trailH, W, trailH)
      }

      // Bloom below the line (4-6px)
      const bloom = ctx.createLinearGradient(0, sy, 0, sy + 6)
      bloom.addColorStop(0, `rgba(245,158,11,${0.14 * op})`)
      bloom.addColorStop(1, 'rgba(245,158,11,0)')
      ctx.fillStyle = bloom
      ctx.fillRect(0, sy, W, 6)

      // Scan line with glow
      ctx.globalAlpha = op
      ctx.strokeStyle = '#f59e0b'
      ctx.lineWidth   = 1.5
      ctx.shadowBlur  = 11
      ctx.shadowColor = 'rgba(245,158,11,0.9)'
      ctx.beginPath()
      ctx.moveTo(0, sy)
      ctx.lineTo(W, sy)
      ctx.stroke()

      ctx.restore()
    }

    function drawFragments(sy, op) {
      ctx.save()
      ctx.font         = '11px "JetBrains Mono", monospace'
      ctx.textBaseline = 'middle'
      ctx.fillStyle    = '#f59e0b'
      for (const slot of state.slots) {
        const dist = sy - slot.y  // negative = scan not yet reached
        let fop = 0
        if (dist >= -FADE_IN_PX && dist < 0) {
          // Approaching: fade in
          fop = ((dist + FADE_IN_PX) / FADE_IN_PX) * PEAK_OP
        } else if (dist >= 0 && dist <= FADE_OUT_PX) {
          // Receding: fade out
          fop = (1 - dist / FADE_OUT_PX) * PEAK_OP
        }
        if (fop > 0.005) {
          ctx.globalAlpha = fop * op
          ctx.fillText(slot.text, slot.x, slot.y)
        }
      }
      ctx.restore()
    }

    function frame(ts) {
      if (!canvas.isConnected) return
      const { W, H } = state
      if (!state.lastTs) state.lastTs = ts
      const dt = Math.min(ts - state.lastTs, 50)
      state.lastTs = ts

      // Smooth opacity toward target (linear, timed to FADE_DUR)
      const diff = state.targetOpacity - state.scanOpacity
      const step = (dt / FADE_DUR) * Math.sign(diff)
      state.scanOpacity = Math.max(0, Math.min(1,
        Math.abs(diff) < Math.abs(step) ? state.targetOpacity : state.scanOpacity + step
      ))

      const op = state.scanOpacity

      if (op > 0.002) {
        state.scanY += (H / SWEEP_MS) * dt
        if (state.scanY >= H) {
          state.scanY = 0
          buildSlots()  // fresh fragment layout; hard reset, no easing
        }
      }

      ctx.clearRect(0, 0, W, H)
      if (op > 0.002) {
        drawScanLine(state.scanY, op)
        drawFragments(state.scanY, op)
      }
      state.rafId = requestAnimationFrame(frame)
    }

    const ro = new ResizeObserver(resize)
    ro.observe(canvas)
    resize()
    state.rafId = requestAnimationFrame(frame)

    return () => {
      ro.disconnect()
      if (state.rafId) cancelAnimationFrame(state.rafId)
    }
  }, [])  // run once — canvas element never changes

  // ── Drive opacity from `active` prop ────────────────────────────────────
  useEffect(() => {
    const state = stateRef.current
    state.targetOpacity = active ? 1 : 0
    if (active) state.scanY = 0  // restart from top on re-activation
  }, [active])

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position:      'absolute',
        inset:         0,
        width:         '100%',
        height:        '100%',
        pointerEvents: 'none',
        zIndex:        0,
        borderRadius:  '5px',
        display:       'block',
      }}
    />
  )
}
