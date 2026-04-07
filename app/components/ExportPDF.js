'use client'

export async function exportToPDF(result, alertText) {
  const { jsPDF } = await import('jspdf')
  const { triage, enrichment, ips, meta } = result

  const doc = new jsPDF({ unit: 'mm', format: 'a4' })
  const W      = 210
  const margin = 20
  const cW     = W - margin * 2
  let y        = 0

  // ── TYPOGRAPHY HELPERS ────────────────────────────────────────────────────
  const amber  = [245, 158, 11]
  const dark   = [15,  20,  30]
  const mid    = [80,  90, 110]
  const light  = [140, 150, 165]
  const rule   = [220, 225, 232]
  const red    = [220,  50,  50]
  const yellow = [200, 150,   0]
  const green  = [30,  160, 100]

  function sevColor(s) {
    if (s === 'CRITICAL') return red
    if (s === 'HIGH')     return amber
    if (s === 'MEDIUM')   return yellow
    return [100, 110, 120]
  }

  function h(size, color, bold = false) {
    doc.setFontSize(size)
    doc.setTextColor(...color)
    doc.setFont('helvetica', bold ? 'bold' : 'normal')
  }

  function mono(size, color) {
    doc.setFontSize(size)
    doc.setTextColor(...color)
    doc.setFont('courier', 'normal')
  }

  function cap(text, x, cy) {
    doc.setFontSize(6.5)
    doc.setTextColor(...light)
    doc.setFont('helvetica', 'normal')
    doc.text(text.toUpperCase(), x, cy)
  }

  function hrule(cy, color = rule) {
    doc.setDrawColor(...color)
    doc.setLineWidth(0.25)
    doc.line(margin, cy, W - margin, cy)
  }

  function wrap(text, x, cy, maxW, size, color, bold = false, lh = 4.8) {
    h(size, color, bold)
    const lines = doc.splitTextToSize(String(text ?? ''), maxW)
    doc.text(lines, x, cy)
    return lines.length * lh
  }

  // ── PAGE BACKGROUND ───────────────────────────────────────────────────────
  doc.setFillColor(255, 255, 255)
  doc.rect(0, 0, W, 297, 'F')

  // ── HEADER ────────────────────────────────────────────────────────────────
  // Reticle mark — centered
  const cx = W / 2
  doc.setDrawColor(...amber)
  doc.setLineWidth(1.4)
  doc.line(cx, 12, cx - 6, 22)      // left leg
  doc.line(cx, 12, cx + 6, 22)      // right leg
  doc.setLineWidth(0.7)
  doc.line(cx - 8.5, 17.5, cx + 8.5, 17.5)  // extended crossbar (reticle)

  // Wordmark
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(15)
  doc.setTextColor(...dark)
  doc.text('ARBITER', cx, 28, { align: 'center' })

  // Subtitle
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(7)
  doc.setTextColor(...light)
  doc.text('AI-POWERED SOC ALERT TRIAGE REPORT', cx, 32.5, { align: 'center' })

  // Amber rule under header
  doc.setDrawColor(...amber)
  doc.setLineWidth(0.6)
  doc.line(margin, 35.5, W - margin, 35.5)

  y = 41

  // ── CASE META ROW ─────────────────────────────────────────────────────────
  // Case ID left, date right
  mono(7.5, mid)
  doc.text(result.id ?? 'ARB-UNKNOWN', margin, y)
  mono(7.5, light)
  doc.text(new Date().toISOString().slice(0, 19) + 'Z', W - margin, y, { align: 'right' })
  y += 4

  mono(7, light)
  doc.text(meta?.alertType ?? 'Windows Security Event', margin, y)
  if (meta?.processingTime) {
    doc.text(`Analyzed in ${(meta.processingTime / 1000).toFixed(1)}s`, W - margin, y, { align: 'right' })
  }
  y += 8

  hrule(y)
  y += 6

  // ── VERDICT ───────────────────────────────────────────────────────────────
  // Severity badge (outline only)
  const sev = triage.severity
  const sc  = sevColor(sev)
  doc.setDrawColor(...sc)
  doc.setLineWidth(0.5)
  doc.roundedRect(margin, y - 4, 22, 6.5, 1, 1)
  doc.setFontSize(7)
  doc.setTextColor(...sc)
  doc.setFont('helvetica', 'bold')
  doc.text(sev, margin + 11, y, { align: 'center' })

  // Classification
  h(17, dark, true)
  doc.text(triage.classification, margin + 26, y)
  y += 6

  // Tactic · MITRE ID · confidence
  h(8, mid)
  doc.text(triage.tactic, margin + 26, y)
  doc.setTextColor(...amber)
  doc.setFont('courier', 'normal')
  doc.text(`  ·  ${triage.mitre_id}`, margin + 26 + doc.getTextWidth(triage.tactic), y)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(...light)
  doc.text(`  ·  ${triage.confidence}% confidence`, margin + 26 + doc.getTextWidth(triage.tactic) + doc.getTextWidth(`  ·  ${triage.mitre_id}`), y)
  y += 10

  hrule(y)
  y += 7

  // ── TWO-COLUMN: MITRE + ASSET ─────────────────────────────────────────────
  const col = (cW - 8) / 2
  const c2x = margin + col + 8

  cap('MITRE ATT&CK', margin, y)
  cap('AFFECTED ASSET', c2x, y)
  y += 4

  mono(9, amber)
  doc.text(triage.mitre_id, margin, y)

  mono(11, dark)
  doc.text(triage.affected_asset, c2x, y)
  y += 4.5

  h(8.5, dark, true)
  doc.text(triage.mitre_name, margin, y)

  if (triage.asset_is_critical) {
    doc.setDrawColor(...red)
    doc.setLineWidth(0.4)
    doc.roundedRect(c2x, y - 3.5, 26, 5.5, 1, 1)
    doc.setFontSize(6.5)
    doc.setTextColor(...red)
    doc.setFont('helvetica', 'bold')
    doc.text('CRITICAL ASSET', c2x + 13, y, { align: 'center' })
  }
  y += 4

  h(7.5, mid)
  doc.text(`${triage.mitre_tactic} · Windows · Security Logs`, margin, y)
  y += 10

  hrule(y)
  y += 7

  // ── EVIDENCE ──────────────────────────────────────────────────────────────
  if (triage.evidence?.length > 0) {
    cap('EVIDENCE — WHY THIS VERDICT', margin, y)
    y += 5

    let ex = margin
    const chipH = 5.5
    triage.evidence.forEach(item => {
      const eqIdx = item.indexOf('=')
      const field = eqIdx > -1 ? item.slice(0, eqIdx) : item
      const val   = eqIdx > -1 ? item.slice(eqIdx + 1, eqIdx + 20) : ''
      const label = val ? `${field} = ${val}${item.slice(eqIdx + 1).length > 19 ? '…' : ''}` : field

      doc.setFont('courier', 'normal')
      doc.setFontSize(7)
      const tw = doc.getTextWidth(label) + 6
      if (ex + tw > W - margin + 2) { ex = margin; y += chipH + 2 }

      doc.setDrawColor(...amber)
      doc.setLineWidth(0.3)
      doc.setFillColor(255, 250, 240)
      doc.roundedRect(ex, y - 3.5, tw, chipH, 1, 1, 'FD')
      doc.setTextColor(...amber)
      doc.text(label, ex + 3, y)
      ex += tw + 3
    })
    y += 12
    hrule(y - 4)
    y += 3
  }

  // ── RECOMMENDATIONS ───────────────────────────────────────────────────────
  cap('RECOMMENDED ACTIONS', margin, y)
  y += 5

  triage.recommendations?.forEach((rec, i) => {
    // Amber numbered circle
    doc.setFillColor(...amber)
    doc.circle(margin + 3, y, 2.8, 'F')
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(6.5)
    doc.setTextColor(255, 255, 255)
    doc.text(String(i + 1), margin + 3, y + 0.8, { align: 'center' })

    // Rec text
    const lh = wrap(rec, margin + 10, y + 0.5, cW - 12, 8, dark, false, 4.5)
    y += Math.max(lh, 6) + 3

    // Connector dot line (not last)
    if (i < triage.recommendations.length - 1) {
      doc.setDrawColor(...rule)
      doc.setLineWidth(0.2)
      doc.line(margin + 3, y - 2, margin + 3, y + 1)
    }
  })

  y += 4
  hrule(y)
  y += 7

  // ── REASONING ─────────────────────────────────────────────────────────────
  cap('ARBITER REASONING', margin, y)
  y += 5

  // Amber left border + light fill
  const reasonLines = doc.splitTextToSize(triage.reasoning ?? '', cW - 8)
  const reasonH     = reasonLines.length * 4.5 + 8
  doc.setFillColor(255, 252, 242)
  doc.roundedRect(margin, y, cW, reasonH, 2, 2, 'F')
  doc.setFillColor(...amber)
  doc.rect(margin, y, 1.8, reasonH, 'F')
  h(8, dark)
  doc.text(reasonLines, margin + 6, y + 5.5)
  y += reasonH + 8

  // ── THREAT INTEL ──────────────────────────────────────────────────────────
  if (ips?.length > 0) {
    if (y > 230) { doc.addPage(); y = 20 }
    hrule(y)
    y += 6
    cap('THREAT INTELLIGENCE', margin, y)
    y += 5

    ips.forEach(ip => {
      const d = enrichment?.[ip]

      mono(10, red)
      doc.text(ip, margin, y)
      y += 5

      const rows = []
      if (d?.abuseipdb) {
        rows.push({ k: 'AbuseIPDB', v: `${d.abuseipdb.score}/100 · ${d.abuseipdb.totalReports} reports · ${d.abuseipdb.isp ?? ''}${d.abuseipdb.isTorNode ? ' · Tor Exit Node' : ''}`, alert: d.abuseipdb.score >= 80 })
      }
      if (d?.virustotal) {
        rows.push({ k: 'VirusTotal', v: `${d.virustotal.malicious}/${d.virustotal.total} engines · AS${d.virustotal.asn ?? ''} ${d.virustotal.asOwner ?? ''}`, alert: d.virustotal.malicious > 0 })
      }
      if (d?.otx) {
        rows.push({ k: 'AlienVault OTX', v: `${d.otx.pulseCount} pulses${d.otx.malwareFamily ? ` · ${d.otx.malwareFamily}` : ''}`, alert: d.otx.pulseCount > 0 })
      }

      rows.forEach(row => {
        cap(row.k, margin + 2, y)
        h(8, row.alert ? red : dark)
        doc.text(row.v, margin + 28, y)
        y += 5
      })
      y += 3
    })
  }

  // ── RAW ALERT ─────────────────────────────────────────────────────────────
  if (y > 220) { doc.addPage(); y = 20 }
  hrule(y)
  y += 6
  cap('RAW ALERT INPUT', margin, y)
  y += 5

  doc.setFillColor(248, 249, 251)
  const rawLines   = doc.splitTextToSize(alertText ?? '', cW - 8)
  const maxLines   = Math.min(rawLines.length, 25)
  const rawH       = maxLines * 3.8 + 7
  doc.roundedRect(margin, y, cW, rawH, 2, 2, 'F')
  mono(6.8, mid)
  doc.text(rawLines.slice(0, maxLines), margin + 4, y + 5)
  if (rawLines.length > maxLines) {
    doc.setTextColor(...light)
    doc.text(`... ${rawLines.length - maxLines} more lines omitted`, margin + 4, y + rawH - 2)
  }
  y += rawH + 8

  // ── FOOTER ────────────────────────────────────────────────────────────────
  const pages = doc.getNumberOfPages()
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p)
    hrule(285)
    doc.setFontSize(6.5)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(...light)
    doc.text('ARBITER · AI-Powered SOC Alert Triage · by Luis Duarte', margin, 290)
    doc.setTextColor(...amber)
    doc.setFont('courier', 'normal')
    doc.text(`Page ${p} of ${pages}`, W - margin, 290, { align: 'right' })
  }

  doc.save(`arbiter-${(result.id ?? 'report').slice(4, 17)}.pdf`)
}