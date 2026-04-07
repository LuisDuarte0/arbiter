'use client'
import { useState } from 'react'

const TABS = [
  { id: 'powershell',    label: 'POWERSHELL' },
  { id: 'cmd',          label: 'CMD / NET' },
  { id: 'investigation', label: 'INVESTIGATION' },
  { id: 'warnings',     label: 'WARNINGS' },
]

function categorizeWarnings(warnings) {
  if (!warnings?.length) return { blockers: [], recommendations: [] }
  const blockerKeywords = ['critical', 'irreversible', 'data loss', 'production', 'outage', 'disrupt', 'block', 'deny', 'isolate', 'disable']
  const blockers = []
  const recommendations = []
  warnings.forEach(w => {
    const lower = w.toLowerCase()
    if (blockerKeywords.some(k => lower.includes(k))) {
      blockers.push(w)
    } else {
      recommendations.push(w)
    }
  })
  return { blockers, recommendations }
}

export default function ContainmentModal({ result, onClose }) {
  const [activeTab, setActiveTab] = useState('powershell')
  const [scripts, setScripts]     = useState(null)
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [copied, setCopied]       = useState(false)

  const { triage, enrichment, ips } = result

  useState(() => {
    async function generate() {
      try {
        const res = await fetch('/api/containment', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ triage, enrichment, ips }),
        })
        const data = await res.json()
        if (data.error) throw new Error(data.error)
        setScripts(data.scripts)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    generate()
  }, [])

  function getActiveContent() {
    if (!scripts) return ''
    if (activeTab === 'powershell')    return scripts.powershell
    if (activeTab === 'cmd')           return scripts.cmd
    if (activeTab === 'investigation') return scripts.investigation
    return ''
  }

  function handleCopy() {
    const content = getActiveContent()
    if (!content) return
    navigator.clipboard.writeText(content)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const { blockers, recommendations } = categorizeWarnings(scripts?.warnings)

  const meta = [
    { label: 'TARGET ASSET',  value: triage.affected_asset },
    { label: 'CLASSIFICATION', value: triage.mitre_id },
    { label: 'PRIVILEGES',    value: 'Administrator' },
    { label: 'SEVERITY',      value: triage.severity },
    { label: 'IMPACT',        value: triage.asset_is_critical ? 'HIGH — Critical Asset' : 'MEDIUM' },
  ]

  return (
    <div
      style={{ position:'fixed', inset:0, background:'rgba(4,6,10,0.88)', zIndex:100, display:'flex', alignItems:'center', justifyContent:'center' }}
      onClick={onClose}
    >
      <div
        style={{ background:'var(--bg-panel)', border:'0.5px solid var(--border-bright)', borderRadius:'8px', width:'80vw', maxWidth:'1000px', height:'84vh', display:'flex', flexDirection:'column', overflow:'hidden' }}
        onClick={e => e.stopPropagation()}
      >

        {/* HEADER */}
        <div style={{ padding:'11px 20px', borderBottom:'0.5px solid var(--border)', display:'flex', alignItems:'center', justifyContent:'space-between', flexShrink:0 }}>
          <div style={{ display:'flex', alignItems:'center', gap:'12px' }}>
            <span style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', letterSpacing:'0.18em', color:'var(--text-muted)', textTransform:'uppercase' }}>CONTAINMENT PLAYBOOK</span>
            <span style={{ background:'var(--red-15)', border:'0.5px solid var(--red-40)', borderRadius:'3px', padding:'2px 8px', fontFamily:'var(--font-mono),monospace', fontSize:'9px', color:'var(--red)', letterSpacing:'0.08em' }} className="arb-warning-pulse">REVIEW BEFORE EXECUTING</span>

          </div>
          <button style={{ background:'none', border:'none', color:'var(--text-muted)', fontSize:'14px', cursor:'pointer', padding:'4px 8px' }} onClick={onClose}>✕</button>
        </div>

        {/* BODY — sidebar + main */}
        <div style={{ flex:1, overflow:'hidden', display:'flex', minHeight:0 }}>

          {/* EXECUTION METADATA SIDEBAR */}
          <div style={{ width:'180px', flexShrink:0, borderRight:'0.5px solid var(--border)', padding:'14px', display:'flex', flexDirection:'column', gap:'0', overflowY:'auto' }}>
            <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', letterSpacing:'0.18em', color:'var(--text-muted)', textTransform:'uppercase', marginBottom:'12px' }}>EXECUTION METADATA</div>
            {meta.map((m, i) => (
              <div key={i} style={{ paddingBottom:'10px', marginBottom:'10px', borderBottom: i < meta.length - 1 ? '0.5px solid var(--border)' : 'none' }}>
                <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.1em', marginBottom:'3px' }}>{m.label}</div>
                <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'10px', color: m.label === 'SEVERITY' && m.value === 'CRITICAL' ? 'var(--red)' : m.label === 'IMPACT' && m.value.startsWith('HIGH') ? 'var(--amber)' : 'var(--text-secondary)', fontWeight:'500', wordBreak:'break-word' }}>{m.value}</div>
              </div>
            ))}
            {scripts?.scope && (
              <div style={{ marginTop:'4px', paddingTop:'10px', borderTop:'0.5px solid var(--border)' }}>
                <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.1em', marginBottom:'4px' }}>SCOPE</div>
                <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', color:'var(--text-secondary)', lineHeight:'1.5' }}>{scripts.scope}</div>
              </div>
            )}
          </div>

          {/* MAIN CONTENT */}
          <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>

            {/* TABS */}
            <div style={{ display:'flex', borderBottom:'0.5px solid var(--border)', flexShrink:0 }}>
              {TABS.map(tab => (
                <button
                  key={tab.id}
                  style={{
                    fontFamily:'var(--font-mono),monospace', fontSize:'9px', letterSpacing:'0.12em',
                    padding:'9px 16px', cursor:'pointer', border:'none', background:'none',
                    color: activeTab === tab.id ? 'var(--amber)' : 'var(--text-muted)',
                    borderBottom: activeTab === tab.id ? '2px solid var(--amber)' : '2px solid transparent',
                  }}
                  onClick={() => setActiveTab(tab.id)}
                >
                  {tab.label}
                  {tab.id === 'warnings' && scripts?.warnings?.length > 0 && (
                    <span style={{ marginLeft:'5px', color:'var(--red)', fontSize:'9px' }}>({scripts.warnings.length})</span>
                  )}
                </button>
              ))}
            </div>

            {/* CONTENT AREA */}
            <div style={{ flex:1, overflowY:'auto', padding:'16px 20px' }}>

              {loading && (
                <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', height:'100%', gap:'12px' }}>
                  <div style={{ width:'8px', height:'8px', borderRadius:'50%', background:'var(--amber)', animation:'blink2 1s ease-in-out infinite' }} />
                  <span style={{ fontFamily:'var(--font-mono),monospace', fontSize:'10px', color:'var(--amber)', letterSpacing:'0.12em' }}>GENERATING CONTAINMENT PLAYBOOK...</span>
                </div>
              )}

              {error && (
                <div style={{ padding:'12px 14px', background:'var(--red-15)', border:'0.5px solid var(--red-40)', borderRadius:'5px', fontFamily:'var(--font-mono),monospace', fontSize:'11px', color:'var(--red)' }}>{error}</div>
              )}

              {scripts && !loading && activeTab !== 'warnings' && (
                <>
                  <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', letterSpacing:'0.15em', color:'var(--text-muted)', textTransform:'uppercase', marginBottom:'10px' }}>
                    {activeTab === 'powershell'    && 'WINDOWS POWERSHELL — RUN AS ADMINISTRATOR'}
                    {activeTab === 'cmd'           && 'COMMAND PROMPT / NET COMMANDS — RUN AS ADMINISTRATOR'}
                    {activeTab === 'investigation' && 'INVESTIGATION QUERIES — VERIFY BEFORE CONTAINMENT'}
                  </div>
                  <div style={{ border:'0.5px solid var(--border-bright)', borderRadius:'5px', overflow:'hidden' }}>
                    <div style={{ background:'var(--bg-card)', padding:'6px 12px', borderBottom:'0.5px solid var(--border)', display:'flex', alignItems:'center', justifyContent:'space-between' }}>
                      <span style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', color:'var(--text-muted)', letterSpacing:'0.15em' }}>
                        {activeTab === 'powershell' && 'POWERSHELL'}
                        {activeTab === 'cmd' && 'CMD / NET'}
                        {activeTab === 'investigation' && 'POWERSHELL · EVENT LOG'}
                      </span>
                      <button
                        onClick={handleCopy}
                        style={{ background:'none', border:'none', color: copied ? 'var(--green)' : 'var(--text-muted)', fontFamily:'var(--font-mono),monospace', fontSize:'8px', letterSpacing:'0.1em', cursor:'pointer', padding:'0' }}
                      >
                        {copied ? 'COPIED ✓' : 'COPY'}
                      </button>
                    </div>
                    <div style={{ background:'#050810', padding:'14px 16px', fontFamily:'var(--font-mono),monospace', fontSize:'11px', color:'var(--text-secondary)', lineHeight:'1.85', whiteSpace:'pre-wrap', wordBreak:'break-word' }}>
                      {getActiveContent()}
                    </div>
                  </div>
                </>
              )}

              {scripts && !loading && activeTab === 'warnings' && (
                <>
                  {blockers.length > 0 && (
                    <>
                      <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', letterSpacing:'0.15em', color:'var(--red)', textTransform:'uppercase', marginBottom:'8px', display:'flex', alignItems:'center', gap:'8px' }}>
                        CRITICAL BLOCKERS
                        <div style={{ flex:1, height:'0.5px', background:'var(--red-40)' }} />
                      </div>
                      <div style={{ display:'flex', flexDirection:'column', gap:'6px', marginBottom:'16px' }}>
                        {blockers.map((w, i) => (
                          <div key={i} style={{ display:'flex', gap:'10px', alignItems:'flex-start', background:'var(--red-15)', border:'0.5px solid var(--red-40)', borderRadius:'4px', padding:'10px 12px' }}>
                            <span style={{ fontFamily:'var(--font-mono),monospace', fontSize:'10px', color:'var(--red)', flexShrink:0, marginTop:'1px' }}>■</span>
                            <span style={{ fontSize:'12.5px', color:'var(--text-secondary)', lineHeight:'1.55' }}>{w}</span>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                  {recommendations.length > 0 && (
                    <>
                      <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'8px', letterSpacing:'0.15em', color:'var(--yellow)', textTransform:'uppercase', marginBottom:'8px', display:'flex', alignItems:'center', gap:'8px' }}>
                        SECURITY RECOMMENDATIONS
                        <div style={{ flex:1, height:'0.5px', background:'var(--yellow-40)' }} />
                      </div>
                      <div style={{ display:'flex', flexDirection:'column', gap:'6px' }}>
                        {recommendations.map((w, i) => (
                          <div key={i} style={{ display:'flex', gap:'10px', alignItems:'flex-start', background:'var(--yellow-15)', border:'0.5px solid var(--yellow-40)', borderRadius:'4px', padding:'10px 12px' }}>
                            <span style={{ fontFamily:'var(--font-mono),monospace', fontSize:'10px', color:'var(--yellow)', flexShrink:0, marginTop:'1px' }}>◆</span>
                            <span style={{ fontSize:'12.5px', color:'var(--text-secondary)', lineHeight:'1.55' }}>{w}</span>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                  {blockers.length === 0 && recommendations.length === 0 && (
                    <div style={{ fontFamily:'var(--font-mono),monospace', fontSize:'10px', color:'var(--text-muted)' }}>No warnings generated.</div>
                  )}
                </>
              )}
            </div>

            {/* FOOTER */}
            {scripts && !loading && activeTab !== 'warnings' && (
              <div style={{ padding:'10px 20px', borderTop:'0.5px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'center', flexShrink:0 }}>
                <span style={{ fontFamily:'var(--font-mono),monospace', fontSize:'9px', color:'var(--text-muted)' }}>
                  ARBITER · {triage.classification} · {triage.affected_asset} · {new Date().toISOString().slice(0,10)}
                </span>
                <button
                  style={{ background: copied ? 'var(--green)' : 'var(--amber)', color:'#080C14', border:'none', borderRadius:'4px', padding:'7px 16px', fontFamily:'var(--font-mono),monospace', fontSize:'10px', letterSpacing:'0.08em', fontWeight:'500', cursor:'pointer' }}
                  onClick={handleCopy}
                >
                  {copied ? 'COPIED ✓' : 'COPY TO CLIPBOARD'}
                </button>
              </div>
            )}

          </div>
        </div>
      </div>
    </div>
  )
}