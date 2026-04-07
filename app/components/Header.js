'use client'
import { useState, useEffect } from 'react'
import AuditLog from './AuditLog'

export default function Header({ activeId, result, onReset }) {
  const [auditOpen, setAuditOpen] = useState(false)
  const [auditCount, setAuditCount] = useState(0)

  useEffect(() => {
    function updateCount() {
      try {
        const logs = JSON.parse(localStorage.getItem('arbiter_audit') ?? '[]')
        setAuditCount(logs.length)
      } catch { setAuditCount(0) }
    }
    updateCount()
    window.addEventListener('storage', updateCount)
    return () => window.removeEventListener('storage', updateCount)
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
          {result && (
            <button
              onClick={onReset}
              style={{
                background: 'none',
                border: '0.5px solid var(--amber-40)',
                borderRadius: '3px',
                color: 'var(--amber)',
                fontFamily: 'var(--font-mono), monospace',
                fontSize: '10px',
                letterSpacing: '0.1em',
                cursor: 'pointer',
                padding: '5px 12px',
                transition: 'background 0.15s',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--amber-15)'}
              onMouseLeave={e => e.currentTarget.style.background = 'none'}
            >
              NEW ANALYSIS
            </button>
          )}
          <button
            className="arb-audit-btn"
            onClick={() => setAuditOpen(true)}
            style={{
              background: auditCount > 0 ? 'var(--amber-15)' : 'none',
              border: '0.5px solid var(--amber-40)',
              color: 'var(--amber)',
            }}
          >
            AUDIT LOG
            {auditCount > 0 && (
              <span className="arb-audit-count">{auditCount}</span>
            )}
          </button>
          <div className="arb-stat">POWERED BY <span>GROQ · LLAMA 3.3</span></div>
          <div className="arb-stat">BY <span>LUIS DUARTE</span></div>
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