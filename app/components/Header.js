'use client'
import { useState, useEffect } from 'react'
import AuditLog from './AuditLog'

export default function Header({ activeId, result }) {
  const severity = result?.triage?.severity ?? null
  const [auditOpen, setAuditOpen] = useState(false)
  const [auditCount, setAuditCount] = useState(0)

  useEffect(() => {
    try {
      const logs = JSON.parse(localStorage.getItem('arbiter_audit') ?? '[]')
      setAuditCount(logs.length)
    } catch { setAuditCount(0) }
  }, [result])

  return (
    <>
      <header className="arb-header">
        <div className="arb-logo">
          <svg viewBox="-8 0 136 120" width="30" height="26" xmlns="http://www.w3.org/2000/svg">
            <line x1="60" y1="8" x2="6" y2="112" stroke="#F59E0B" strokeWidth="17" strokeLinecap="square"/>
            <line x1="60" y1="8" x2="114" y2="112" stroke="#F59E0B" strokeWidth="17" strokeLinecap="square"/>
            <line x1="-6" y1="68" x2="126" y2="68" stroke="#F59E0B" strokeWidth="7" strokeLinecap="square"/>
          </svg>
          <span className="arb-wordmark">ARBITER</span>
        </div>
        <div className="arb-hdivider" />
        <div className="arb-hmeta">
          <div className="arb-case-id">{activeId ?? 'NO ACTIVE CASE'}</div>
          <div className="arb-case-sub">
            {result ? `${result.triage.tactic.toUpperCase()} · ANALYSIS COMPLETE` : 'AWAITING ALERT INPUT'}
          </div>
        </div>
        <div className="arb-hright">
          {severity && (
            <div className={`arb-badge arb-${severity.toLowerCase()}`}>{severity}</div>
          )}
          <button className="arb-audit-btn" onClick={() => setAuditOpen(true)}>
            AUDIT LOG
            {auditCount > 0 && <span className="arb-audit-count">{auditCount}</span>}
          </button>
          <div className="arb-stat">POWERED BY <span>GROQ · LLAMA 3.3</span></div>
          <div className="arb-hdivider" />
          <div className="arb-live">
            <div className="arb-dot" />
            LIVE
          </div>
        </div>
      </header>
      {auditOpen && <AuditLog onClose={() => setAuditOpen(false)} />}
    </>
  )
}