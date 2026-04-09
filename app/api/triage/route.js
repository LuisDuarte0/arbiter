export const maxDuration = 60

import Groq from 'groq-sdk'
import { Redis } from '@upstash/redis'

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY })

const redis = new Redis({
  url:   process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
})

// ── REDIS TEMPORAL CORRELATION ────────────────────────────────────────────────
const REDIS_TTL = 86400 // 24 hours

async function getRedisContext(ips, username, sessionId) {
  const prefix = `session:${sessionId}:`
  const keys = []
  if (ips.length) ips.forEach(ip => keys.push(`${prefix}ip:${ip}`))
  if (username) keys.push(`${prefix}user:${username}`)
  if (!keys.length) return null
  try {
    const results = await Promise.all(keys.map(k => redis.get(k)))
    const hits = results.map((r, i) => r ? { key: keys[i], ...r } : null).filter(Boolean)
    if (!hits.length) return null

    const userHit = hits.find(h => h.key.includes(':user:'))
    const ipHit   = hits.find(h => h.key.includes(':ip:'))
    const patterns = []
    if (userHit) {
      const uniqueUserAssets = [...new Set((userHit.assets ?? []).filter(Boolean))]
      if (uniqueUserAssets.length >= 2) {
        patterns.push({ type: 'user_multihost', label: `USER ON MULTIPLE HOSTS — ${uniqueUserAssets.length} unique hosts`, assets: uniqueUserAssets, count: userHit.count ?? 1 })
      }
    }
    if (ipHit) {
      const uniqueIpAssets = [...new Set((ipHit.assets ?? []).filter(Boolean))]
      if (uniqueIpAssets.length >= 2) {
        patterns.push({ type: 'ip_multitarget', label: `IP TARGETING MULTIPLE ASSETS — ${uniqueIpAssets.length} targets`, assets: uniqueIpAssets, count: ipHit.count ?? 1 })
      }
    }
    if (userHit && ipHit && userHit.count >= 2 && ipHit.count >= 2) {
      patterns.push({ type: 'user_ip_linked', label: 'LINKED INDICATORS — user and IP co-occur across multiple events', count: Math.max(userHit.count ?? 1, ipHit.count ?? 1) })
    }

    return { hits, patterns }
  } catch { return null }
}

async function writeRedisContext(ips, username, triage, caseId, sessionId) {
  const prefix = `session:${sessionId}:`
  const now = Date.now()
  const entry = {
    caseId,
    severity: triage.severity,
    classification: triage.classification,
    affectedAsset: triage.affected_asset,
    timestamp: now,
  }
  const writes = []
  ips.forEach(ip => {
    const key = `${prefix}ip:${ip}`
    writes.push(
      redis.get(key).then(existing => {
        const prev = existing ?? { count: 0, cases: [], assets: [] }
        const updated = {
          ...entry,
          count: prev.count + 1,
          cases: [caseId, ...(prev.cases ?? [])].slice(0, 10),
          assets: [...new Set([...(triage.allAffectedAssets ?? [triage.affected_asset]).filter(Boolean), ...(prev.assets ?? [])].filter(Boolean))].slice(0, 10),
        }
        return redis.set(key, updated, { ex: REDIS_TTL })
      })
    )
  })
  if (username && username !== 'system' && !username.includes('$')) {
    const key = `${prefix}user:${username}`
    writes.push(
      redis.get(key).then(existing => {
        const prev = existing ?? { count: 0, cases: [], assets: [] }
        const updated = {
          ...entry,
          count: prev.count + 1,
          cases: [caseId, ...(prev.cases ?? [])].slice(0, 10),
          assets: [...new Set([...(triage.allAffectedAssets ?? [triage.affected_asset]).filter(Boolean), ...(prev.assets ?? [])].filter(Boolean))].slice(0, 10),
        }
        return redis.set(key, updated, { ex: REDIS_TTL })
      })
    )
  }
  try { await Promise.all(writes) } catch { }
}

function buildRedisContextSummary(hits) {
  if (!hits?.length) return null
  return hits.map(h => {
    const age = Math.round((Date.now() - h.timestamp) / 60000)
    const rawKey = h.key.split(':').slice(2).join(':')
    const indicator = rawKey.startsWith('ip:') ? `IP ${rawKey.slice(3)}` : `User ${rawKey.slice(5)}`
    return `${indicator}: seen ${h.count}× in last 24h | last severity=${h.severity} | assets=[${(h.assets ?? []).join(', ')}] | ${age}min ago | cases=[${(h.cases ?? []).slice(0,3).join(', ')}]`
  }).join('\n')
}

// ── PROMPT INJECTION SANITIZER ────────────────────────────────────────────────
// Treats all log input as untrusted. Strips instruction-like patterns.
function sanitizeAlertText(text) {
  return text
    .replace(/\b(ignore|disregard|forget|override|bypass|you are|act as|pretend|system prompt|new instruction|jailbreak)\b.{0,80}/gi, '[REDACTED]')
    .replace(/(?:[A-Za-z0-9+/]{40,}={0,2})/g, '[BASE64_BLOB]')
    .replace(/"/g, "'")
    .trim()
}

// ── HARDENED ALERT PRE-PARSER ─────────────────────────────────────────────────
// Multi-format: key=value, JSON, Sysmon Image field, CEF. Never throws.
function parseAlert(text) {
  // Try JSON first
  let jsonObj = null
  const jsonMatch = text.match(/\{[\s\S]+\}/)
  if (jsonMatch) {
    try { jsonObj = JSON.parse(jsonMatch[0]) } catch { /* not JSON */ }
  }

  function get(jsonKeys, pattern) {
    if (jsonObj) {
      for (const k of jsonKeys) {
        const val = jsonObj[k] ?? jsonObj[k.toLowerCase()] ?? jsonObj[k.toUpperCase()]
        if (val != null) return String(val).trim()
      }
    }
    return text.match(pattern)?.[1]?.trim() ?? null
  }

  function normalizeUsername(raw) {
    if (!raw) return null
    const stripped = raw.includes('\\') ? raw.split('\\').pop() : raw
    return stripped.replace(/[<>"'`]/g, '').toLowerCase()
  }

  function normalizeAsset(raw) {
    if (!raw) return null
    return raw.replace(/[<>"'`]/g, '').toUpperCase().trim()
  }

  const rawUsername = get(
    ['TargetUserName','SubjectUserName','Username','User','user_name','actor'],
    /(?:User Name|TargetUserName|SubjectUserName|Username|User)[=:\s]+(\S+)/i
  )
  const rawAsset = get(
    ['WorkstationName','ComputerName','Hostname','host','computer','device'],
    /(?:WorkstationName|ComputerName|Hostname|host)[=:\s]+(\S+)/i
  )

  const allAssets = (() => {
    const fromText = (text.match(/(?:WorkstationName|ComputerName|Hostname)[=:\s]+(\S+)/gi) ?? [])
      .map(m => m.trim().split(/[=:\s]+/).pop())
    return [...new Set(fromText)].map(normalizeAsset).filter(Boolean).join(', ')
  })()

  const allEventCodes = (() => {
    const fromText = (text.match(/EventCode[=:\s]+(\d+)/gi) ?? []).map(m => m.trim().split(/[=:\s]+/).pop())
    return [...new Set(fromText)].join(', ')
  })()

  const rawEventId = get(['EventCode','eventId','event_id','EventID'], /EventCode[=:\s]+(\d+)/i)

  return {
    eventId:       rawEventId,
    logonType:     get(['LogonType','logon_type'], /LogonType[=:\s]+(\d+)/i),
    failureReason: get(['FailureReason','Status'], /(?:FailureReason|Status)[=:\s]+(%%\d+|0x[0-9a-fA-F]+)/i),
    username:        rawUsername ? normalizeUsername(rawUsername) : null,
    usernameRaw:     rawUsername ?? null,
    targetUsername:  get(['TargetUserName'], /TargetUserName[=:\s]+(\S+)/i),
    domain:        get(['TargetDomainName','Domain'], /(?:TargetDomainName|Domain)[=:\s]+(\S+)/i),
    // Sysmon uses Image, standard logs use ProcessName/NewProcessName
    processName:   get(['ProcessName','Image','NewProcessName','process_name'], /(?:New Process Name|ProcessName|NewProcessName|Image)[=:\s]+(.+?)(?:\r?\n|$)/i),
    commandLine:   get(['CommandLine','ProcessCommandLine','command_line','Process Command Line'], /(?:Process Command Line|CommandLine|ProcessCommandLine)[=:\s]+(.+?)(?:\r?\n|$)/i),
    asset:         rawAsset ? normalizeAsset(rawAsset) : null,
    allAssets,
    allEventCodes,
    count:         get(['Count','count'], /Count[=:\s]+(\d+)/i),
    fileHash:      get(['MD5','SHA1','SHA256','Hashes'], /(?:MD5|SHA1|SHA256|Hashes)[=:\s]+([a-fA-F0-9]{32,64})/i),
    parentProcess: get(['ParentProcessName','ParentImage'], /(?:Parent Process Name|ParentProcessName|ParentImage)[=:\s]+(.+?)(?:\r?\n|$)/i),
    serviceName:   get(['ServiceName'], /ServiceName[=:\s]+(\S+)/i),
    taskName:      get(['TaskName'], /TaskName[=:\s]+(.+?)(?:\r?\n|$)/i),
    taskContent:   get(['TaskContent'], /TaskContent[=:\s]+(.+?)(?:\r?\n|$)/i),
    objectName:    get(['ObjectName','TargetObject'], /(?:ObjectName|TargetObject)[=:\s]+(.+?)(?:\r?\n|$)/i),
    alertType:     detectAlertType(text, jsonObj),
    parseQuality:  rawEventId ? 'structured' : 'partial',
  }
}

function detectAlertType(text, jsonObj) {
  if (jsonObj?.eventSource?.includes('amazonaws') || jsonObj?.source === 'cloudtrail') return 'AWS CloudTrail'
  if (/EventCode|Security-Auditing|Microsoft-Windows/i.test(text)) return 'Windows Security Event'
  if (/CEF:|syslog|facility/i.test(text)) return 'Syslog/CEF'
  if (/eventSource.*amazonaws|CloudTrail/i.test(text)) return 'AWS CloudTrail'
  if (/crowdstrike|defender|sentinel|edr/i.test(text)) return 'EDR Alert'
  if (/\"alert\"|\"rule\"|\"signature\"/i.test(text)) return 'IDS/IPS Alert'
  return 'Generic Log'
}

// ── HARDENED IP EXTRACTION ────────────────────────────────────────────────────
// IPv4, IPv6, IPv4-mapped (::ffff:), IPs inside URLs and JSON.
function extractIPs(text) {
  const found = new Set()

  // IPv4
  for (const match of text.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
    const ip = match[0]
    const p = ip.split('.').map(Number)
    if (p.some(n => n > 255)) continue
    if (p[0] === 0 || p[0] === 127) continue
    if (p[0] === 10) continue
    if (p[0] === 192 && p[1] === 168) continue
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) continue
    if (p[0] === 169 && p[1] === 254) continue
    found.add(ip)
  }

  // IPv4-mapped IPv6 (::ffff:1.2.3.4)
  for (const match of text.matchAll(/::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gi)) {
    const ip = match[1]
    const p = ip.split('.').map(Number)
    if (!p.some(n => n > 255) && p[0] !== 10 && p[0] !== 127 &&
        !(p[0] === 192 && p[1] === 168) &&
        !(p[0] === 172 && p[1] >= 16 && p[1] <= 31)) {
      found.add(ip)
    }
  }

  // IPv6 — non-loopback, non-link-local, non-private
  for (const match of text.matchAll(/\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b/g)) {
    const ip = match[0]
    if (ip === '::1') continue
    if (ip.toLowerCase().startsWith('fe80')) continue
    if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) continue
    found.add(ip)
  }

  return [...found]
}

// ── ENRICHMENT SOURCE HEALTH ───────────────────────────────────────────────────
function getEnrichmentHealth(enrichment, ips) {
  if (!ips.length) return { healthy: [], failed: ['abuseipdb','virustotal','otx'], noIp: true, partial: false }
  const sources = ['abuseipdb', 'virustotal', 'otx']
  const failed = []
  const healthy = []
  sources.forEach(src => {
    const allNull = ips.every(ip => enrichment[ip]?.[src] === null)
    if (allNull) failed.push(src)
    else healthy.push(src)
  })
  return { healthy, failed, partial: failed.length > 0 && healthy.length > 0, noIp: false }
}

// ── POST-LLM DETERMINISTIC VALIDATION & OVERRIDE ──────────────────────────────
// Rules enforced regardless of LLM output. LLM cannot violate these.
function validateAndOverrideTriage(triage, parsedAlert, enrichmentJudgment, redisHits) {
  const overrides = []

  // 1. Field sync — tactic must equal mitre_tactic
  if (triage.tactic !== triage.mitre_tactic) {
    triage.tactic = triage.mitre_tactic
    overrides.push('tactic_sync')
  }

  // 2. Classification must not contain MITRE ID
  if (/T\d{4}(\.\d{3})?/.test(triage.classification)) {
    triage.classification = triage.classification.replace(/T\d{4}(\.\d{3})?\s*/g, '').trim()
    overrides.push('classification_cleaned')
  }

  // 3. Severity floor — confirmed malicious enrichment cannot result in LOW/MEDIUM
  if (enrichmentJudgment.judgment === 'CONFIRMED_MALICIOUS' && ['LOW', 'MEDIUM'].includes(triage.severity)) {
    triage.severity = 'HIGH'
    overrides.push('severity_floor_enrichment')
  }

  // 4. Severity floor — active campaign cannot be below CRITICAL
  const frequencyMultiplier = redisHits?.reduce((max, h) => Math.max(max, h.count ?? 0), 0) ?? 0
  const uniqueAssets = redisHits?.reduce((set, h) => { (h.assets ?? []).forEach(a => set.add(a)); return set }, new Set())?.size ?? 0
  if (frequencyMultiplier >= 2 && uniqueAssets >= 2 && triage.severity !== 'CRITICAL') {
    triage.severity = 'CRITICAL'
    overrides.push('severity_floor_campaign')
  }

  // 5. Asset criticality — enforce deterministically
  const triageAssetName = (triage.affected_asset ?? '').toUpperCase()
  const knownCriticalPatterns = /\b(DC|PDC|BDC|ADC|ADDC|SQL|DB[-_]|[-_]DB|ORA|ORACLE|POSTGRES|MYSQL|BACKUP|BKP|VEEAM|EXCHANGE|EXCH|MAIL)\b/i
  if (knownCriticalPatterns.test(triageAssetName) && !triage.asset_is_critical) {
    triage.asset_is_critical = true
    overrides.push('asset_criticality_enforced')
  }
  // SRV alone is NOT critical
  if (/^[A-Z0-9-]*SRV[A-Z0-9-]*$/.test(triageAssetName) && !knownCriticalPatterns.test(triageAssetName) && triage.asset_is_critical) {
    triage.asset_is_critical = false
    overrides.push('asset_criticality_corrected')
  }

  // 6. Confidence bounds
  triage.confidence = Math.max(0, Math.min(100, Math.round(triage.confidence ?? 50)))

  // 7. Remove RFC 1918 block recommendations
  if (Array.isArray(triage.recommendations)) {
    triage.recommendations = triage.recommendations.map((rec, i) => {
      if (/block.*(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(rec)) {
        overrides.push(`rec_${i}_rfc1918_removed`)
        return 'Isolate affected host from network segment pending investigation.'
      }
      return rec
    })
  }

  // 8. Remove evidence-destroying commands
  if (Array.isArray(triage.recommendations)) {
    triage.recommendations = triage.recommendations.map((rec, i) => {
      if (/wevtutil.*(clear|cl\b)|del.*\.evtx|Clear-EventLog/i.test(rec)) {
        overrides.push(`rec_${i}_evidence_destruction_removed`)
        return 'Preserve all logs — do not clear event logs during active investigation.'
      }
      return rec
    })
  }

  // GUARANTEE 5 ACTIONABLE RECOMMENDATIONS WITH PROVENANCE
  const actionablePatterns = [
    /^Run:/i, /^Isolate/i, /^Block/i, /^Collect/i, /^Disable/i,
    /^Delete/i, /^Remove/i, /^Terminate/i, /Get-WinEvent/i,
    /net user/i, /schtasks/i, /sc stop/i, /netstat/i, /Invoke-/i,
  ]

  const isActionable = (rec) => actionablePatterns.some(p => p.test(rec?.trim() ?? ''))

  const triageAsset = triage.affected_asset ?? 'AFFECTED_HOST'
  const user        = parsedAlert?.username ?? 'AFFECTED_USER'
  const evtId       = parsedAlert?.eventId ?? '4688'

  const actionablePool = [
    { rec: `Run: Get-WinEvent -FilterHashtable @{LogName='Security'; Id=${evtId}} -ComputerName ${triageAsset} | Select -First 50`, prov: 'forensic' },
    { rec: `Run: net user ${user} /domain /active:no — disable ${user} pending investigation`, prov: 'account_action' },
    { rec: `Isolate ${triageAsset} from network — active compromise confirmed by deterministic engine`, prov: 'behavioral_heuristic' },
    { rec: `Collect memory image from ${triageAsset} before shutdown — volatile evidence preservation`, prov: 'forensic' },
    { rec: `Run: schtasks /query /fo LIST /v on ${triageAsset} — audit all scheduled tasks for persistence`, prov: 'forensic' },
  ]

  // Replace non-actionable recommendations
  triage.recommendations = (triage.recommendations ?? []).map((rec, i) => {
    if (!isActionable(rec)) {
      overrides.push(`rec_${i}_non_actionable_replaced`)
      return actionablePool[i]?.rec ?? actionablePool[0].rec
    }
    return rec
  })

  // Pad to exactly 5
  while (triage.recommendations.length < 5) {
    const idx = triage.recommendations.length
    triage.recommendations.push(actionablePool[idx]?.rec ?? actionablePool[0].rec)
    overrides.push(`rec_${idx}_padded`)
  }

  // Trim to exactly 5
  if (triage.recommendations.length > 5) {
    triage.recommendations = triage.recommendations.slice(0, 5)
    overrides.push('recommendations_trimmed_to_5')
  }

  // Guarantee provenance array matches length
  const defaultProvenance = ['forensic', 'account_action', 'behavioral_heuristic', 'forensic', 'forensic']
  triage.recommendation_provenance = Array.from({ length: 5 }, (_, i) =>
    triage.recommendation_provenance?.[i] ?? defaultProvenance[i]
  )

  return { triage, overrides }
}

// ── DECISION ENGINE ───────────────────────────────────────────────────────────

function getSignals(parsed, enrichmentJudgment, redisHits) {
  const signals = []

  const asset = (parsed.asset ?? '').toUpperCase()
  const allAssets = (parsed.allAssets ?? '').toUpperCase()
  const combinedAssets = `${asset} ${allAssets}`

  const criticalPatterns = [
    { pattern: /\b(DC|PDC|BDC|ADC|ADDC)\b/, label: 'Domain Controller targeted', severity: 'CRITICAL', confidence: 95, weight: 5 },
    { pattern: /\b(EXCHANGE|EXCH|MAIL)\b/, label: 'Mail server targeted', severity: 'CRITICAL', confidence: 90, weight: 5 },
    { pattern: /\b(SQL|DB[-_]|[-_]DB|ORA|ORACLE|POSTGRES|MYSQL)\b/, label: 'Database server targeted', severity: 'HIGH', confidence: 88, weight: 4 },
    { pattern: /\b(BACKUP|BKP|VEEAM)\b/, label: 'Backup infrastructure targeted', severity: 'HIGH', confidence: 85, weight: 4 },
    { pattern: /\b(PROD|PRODUCTION)\b/, label: 'Production system targeted', severity: 'HIGH', confidence: 80, weight: 3 },
  ]

  for (const cp of criticalPatterns) {
    if (cp.pattern.test(combinedAssets)) {
      signals.push({ rule: 'ASSET_CRITICAL', label: cp.label, severity: cp.severity, confidence: cp.confidence, weight: cp.weight, evidence: [`asset=${parsed.asset ?? parsed.allAssets}`], category: 'asset', source: 'parser' })
      break
    }
  }

  const count = parseInt(parsed.count ?? '0', 10)
  const eventIds = (parsed.allEventCodes ?? parsed.eventId ?? '').split(',').map(s => s.trim())

  if (eventIds.includes('4625') || eventIds.includes('4771')) {
    if (count > 100) signals.push({ rule: 'BRUTE_FORCE_EXTREME', label: 'Extreme brute force volume', severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`EventCode=4625`, `Count=${count}`], category: 'behavioral', source: 'parser', mitre: 'T1110.001' })
    else if (count > 20) signals.push({ rule: 'BRUTE_FORCE_HIGH', label: 'High-volume brute force', severity: 'CRITICAL', confidence: 90, weight: 4, evidence: [`EventCode=4625`, `Count=${count}`], category: 'behavioral', source: 'parser', mitre: 'T1110.001' })
    else if (count > 5) signals.push({ rule: 'BRUTE_FORCE_MEDIUM', label: 'Repeated failed logons', severity: 'HIGH', confidence: 75, weight: 3, evidence: [`EventCode=4625`, `Count=${count}`], category: 'behavioral', source: 'parser', mitre: 'T1110.001' })
    else signals.push({ rule: 'LOGON_FAILURE_LOW', label: 'Low-count logon failure', severity: 'LOW', confidence: 70, weight: 1, evidence: [`EventCode=4625`, `Count=${count || '1'}`], category: 'behavioral', source: 'parser', mitre: 'T1110' })
  }

  const cmdLine = (parsed.commandLine ?? '').toLowerCase()
  const procName = (parsed.processName ?? '').toLowerCase()
  const parentProc = (parsed.parentProcess ?? '').toLowerCase()

  if (procName.includes('certutil') && /-urlcache|-split|-f/.test(cmdLine)) {
    signals.push({ rule: 'LOLBIN_CERTUTIL_DOWNLOAD', label: 'certutil used as download cradle', severity: 'HIGH', confidence: 92, weight: 5, evidence: [`ProcessName=${parsed.processName}`, `CommandLine=${parsed.commandLine?.slice(0,80)}`], category: 'behavioral', source: 'parser', mitre: 'T1105' })
    if (/users\\public|windows\\temp|programdata/i.test(cmdLine))
      signals.push({ rule: 'LOLBIN_CERTUTIL_SUSPICIOUS_PATH', label: 'certutil writing to suspicious path', severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`CommandLine=${parsed.commandLine?.slice(0,80)}`], category: 'behavioral', source: 'parser', mitre: 'T1105' })
  }

  if (procName.includes('mshta') && /http[s]?:\/\//i.test(cmdLine))
    signals.push({ rule: 'LOLBIN_MSHTA_REMOTE', label: 'mshta executing remote content', severity: 'HIGH', confidence: 90, weight: 5, evidence: [`ProcessName=${parsed.processName}`, `CommandLine=${parsed.commandLine?.slice(0,80)}`], category: 'behavioral', source: 'parser', mitre: 'T1218.005' })

  const officeParents = ['winword.exe','excel.exe','powerpnt.exe','outlook.exe']
  const lolbins = ['mshta.exe','wscript.exe','cscript.exe','powershell.exe','cmd.exe','certutil.exe','regsvr32.exe','rundll32.exe']
  if (officeParents.some(p => parentProc.includes(p)) && lolbins.some(l => procName.includes(l)))
    signals.push({ rule: 'OFFICE_MACRO_DROPPER', label: 'Office application spawning LOLBin', severity: 'CRITICAL', confidence: 98, weight: 5, evidence: [`ParentProcess=${parsed.parentProcess}`, `ProcessName=${parsed.processName}`], category: 'behavioral', source: 'parser', mitre: 'T1204.002' })

  if (procName.includes('powershell') && /-enc\b|-encodedcommand/i.test(cmdLine))
    signals.push({ rule: 'POWERSHELL_ENCODED', label: 'Encoded PowerShell command', severity: 'HIGH', confidence: 85, weight: 4, evidence: [`ProcessName=${parsed.processName}`, `CommandLine=${parsed.commandLine?.slice(0,80)}`], category: 'behavioral', source: 'parser', mitre: 'T1059.001' })

  if (eventIds.includes('4698') || eventIds.includes('4702')) {
    const taskContent = (parsed.taskContent ?? parsed.commandLine ?? parsed.taskName ?? '').toLowerCase()
    if (/iex|invoke-expression|downloadstring|-enc|certutil/i.test(taskContent))
      signals.push({ rule: 'SCHEDULED_TASK_CRADLE', label: 'Scheduled task with download cradle', severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`EventCode=4698`, `TaskName=${parsed.taskName}`, `Content=${taskContent.slice(0,60)}`], category: 'behavioral', source: 'parser', mitre: 'T1053.005' })
    else
      signals.push({ rule: 'SCHEDULED_TASK_CREATED', label: 'Scheduled task created', severity: 'MEDIUM', confidence: 60, weight: 2, evidence: [`EventCode=4698`, `TaskName=${parsed.taskName}`], category: 'behavioral', source: 'parser', mitre: 'T1053.005' })
  }

  if (eventIds.includes('4697') || eventIds.includes('7045')) {
    const svcPath = (parsed.commandLine ?? parsed.objectName ?? '').toLowerCase()
    if (/users\\public|windows\\temp|programdata|appdata/i.test(svcPath))
      signals.push({ rule: 'SERVICE_SUSPICIOUS_PATH', label: 'Service binary in suspicious path', severity: 'CRITICAL', confidence: 93, weight: 5, evidence: [`EventCode=4697`, `ServiceName=${parsed.serviceName}`, `Path=${svcPath.slice(0,60)}`], category: 'behavioral', source: 'parser', mitre: 'T1543.003' })
  }

  if (eventIds.includes('1102') || eventIds.includes('4719'))
    signals.push({ rule: 'AUDIT_LOG_CLEARED', label: 'Security audit log cleared', severity: 'CRITICAL', confidence: 98, weight: 5, evidence: [`EventCode=${eventIds.includes('1102') ? '1102' : '4719'}`], category: 'behavioral', source: 'parser', mitre: 'T1070.001' })

  if (eventIds.includes('4720')) {
    const targetUser = (parsed.targetUsername ?? parsed.username ?? '').toLowerCase()
    const isSuspiciousName = /backdoor|hack|persist|0day|temp|svc_|_svc|admin_/i.test(targetUser)
    if (isSuspiciousName) {
      signals.push({ rule: 'ACCOUNT_CREATED_SUSPICIOUS', label: `Suspicious account created: ${parsed.targetUsername ?? parsed.username}`, severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`EventCode=4720`, `TargetUserName=${parsed.targetUsername ?? parsed.username}`, `CreatedBy=${parsed.username}`], category: 'behavioral', source: 'parser', mitre: 'T1136.001' })
    } else {
      signals.push({ rule: 'ACCOUNT_CREATED', label: 'New user account created', severity: 'MEDIUM', confidence: 65, weight: 3, evidence: [`EventCode=4720`, `TargetUserName=${parsed.targetUsername ?? parsed.username}`], category: 'behavioral', source: 'parser', mitre: 'T1136.001' })
    }
  }

  if (eventIds.includes('4663') || eventIds.includes('4656')) {
    const obj = (parsed.objectName ?? '').toLowerCase()
    if (obj.includes('ntds.dit')) signals.push({ rule: 'NTDS_ACCESS', label: 'ntds.dit accessed', severity: 'CRITICAL', confidence: 99, weight: 5, evidence: [`EventCode=4663`, `ObjectName=${parsed.objectName}`], category: 'behavioral', source: 'parser', mitre: 'T1003.003' })
    else if (obj.includes('sam')) signals.push({ rule: 'SAM_ACCESS', label: 'SAM database accessed', severity: 'CRITICAL', confidence: 96, weight: 5, evidence: [`EventCode=4663`, `ObjectName=${parsed.objectName}`], category: 'behavioral', source: 'parser', mitre: 'T1003.002' })
  }

  if (procName && cmdLine) {
    const isRundll32 = procName.includes('rundll32')
    const isLsassDump = /comsvcs|minidump|lsass/i.test(cmdLine)
    const isMimikatz = /mimikatz|sekurlsa|privilege::debug/i.test(cmdLine)
    if (isRundll32 && isLsassDump) {
      signals.push({ rule: 'LSASS_DUMP_RUNDLL32', label: 'LSASS memory dump via rundll32/comsvcs', severity: 'CRITICAL', confidence: 99, weight: 5, evidence: [`ProcessName=${parsed.processName}`, `CommandLine=${parsed.commandLine?.slice(0,80)}`], category: 'behavioral', source: 'parser', mitre: 'T1003.001' })
    }
    if (isMimikatz) {
      signals.push({ rule: 'MIMIKATZ_DETECTED', label: 'Mimikatz credential dumping detected', severity: 'CRITICAL', confidence: 99, weight: 5, evidence: [`CommandLine=${parsed.commandLine?.slice(0,80)}`], category: 'behavioral', source: 'parser', mitre: 'T1003.001' })
    }
  }

  const verdict = enrichmentJudgment?.judgment
  if (verdict === 'CONFIRMED_MALICIOUS') signals.push({ rule: 'ENRICHMENT_CONFIRMED_MALICIOUS', label: 'IP confirmed malicious', severity: 'HIGH', confidence: 80, weight: 3, evidence: [`enrichmentVerdict=CONFIRMED_MALICIOUS`], category: 'enrichment', source: 'enrichment', mitre: null })
  else if (verdict === 'SUSPICIOUS') signals.push({ rule: 'ENRICHMENT_SUSPICIOUS', label: 'IP flagged suspicious', severity: 'MEDIUM', confidence: 60, weight: 2, evidence: [`enrichmentVerdict=SUSPICIOUS`], category: 'enrichment', source: 'enrichment', mitre: null })
  else if (verdict === 'CLEAN') signals.push({ rule: 'ENRICHMENT_CLEAN', label: 'IP clean across all sources', severity: 'LOW', confidence: 50, weight: 1, evidence: [`enrichmentVerdict=CLEAN`], category: 'enrichment', source: 'enrichment', mitre: null })

  if (redisHits?.length > 0) {
    const maxCount = redisHits.reduce((max, h) => Math.max(max, h.count ?? 0), 0)
    const uniqueAssets = new Set(redisHits.flatMap(h => h.assets ?? [])).size
    if (maxCount >= 2 && uniqueAssets >= 2) signals.push({ rule: 'ACTIVE_CAMPAIGN', label: `Active campaign — ${maxCount} hits across ${uniqueAssets} assets`, severity: 'CRITICAL', confidence: 90, weight: 5, evidence: [`redisHits=${maxCount}`, `uniqueAssets=${uniqueAssets}`], category: 'frequency', source: 'redis', mitre: 'T1078' })
    else if (maxCount >= 2) signals.push({ rule: 'REPEATED_INDICATOR', label: `Indicator seen ${maxCount}× in last 24h`, severity: 'HIGH', confidence: 75, weight: 3, evidence: [`redisHits=${maxCount}`], category: 'frequency', source: 'redis', mitre: 'T1078' })
  }

  return signals
}

function aggregateSignals(signals, parseQuality = 'structured') {
  if (!signals.length) return { severity: 'LOW', classification: 'UNKNOWN', confidence: 20, asset_is_critical: false, evidence: [], decision_trace: ['No rules matched — defaulting to LOW/UNKNOWN'] }

  const categoryPriority = { behavioral: 4, asset: 3, frequency: 2, enrichment: 1 }
  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

  const sorted = [...signals].sort((a, b) => {
    const catDiff = (categoryPriority[b.category] ?? 0) - (categoryPriority[a.category] ?? 0)
    if (catDiff !== 0) return catDiff
    const weightDiff = b.weight - a.weight
    if (weightDiff !== 0) return weightDiff
    return b.confidence - a.confidence
  })

  const dominant = sorted[0]
  const hasBehavioral = signals.some(s => s.category === 'behavioral' || s.category === 'asset')
  let finalSeverityRank = severityRank[dominant.severity] ?? 1

  for (const sig of signals) {
    if (hasBehavioral && sig.category === 'enrichment' && sig.severity === 'LOW') continue
    const rank = severityRank[sig.severity] ?? 1
    if (rank > finalSeverityRank) finalSeverityRank = rank
  }

  const severityByRank = { 4: 'CRITICAL', 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW' }
  const finalSeverity = severityByRank[finalSeverityRank] ?? 'LOW'
  const assetIsCritical = signals.some(s => s.category === 'asset' && ['CRITICAL','HIGH'].includes(s.severity))

  const classificationMap = {
    BRUTE_FORCE_EXTREME: 'Brute Force Attack', BRUTE_FORCE_HIGH: 'Brute Force Attack',
    BRUTE_FORCE_MEDIUM: 'Password Spraying', LOGON_FAILURE_LOW: 'Failed Logon',
    LOLBIN_CERTUTIL_DOWNLOAD: 'Malicious File Download via LOLBin',
    LOLBIN_CERTUTIL_SUSPICIOUS_PATH: 'LOLBin Staging to Suspicious Path',
    LOLBIN_MSHTA_REMOTE: 'Remote Script Execution via mshta',
    OFFICE_MACRO_DROPPER: 'Macro-based Dropper Execution',
    POWERSHELL_ENCODED: 'Encoded PowerShell Execution',
    SCHEDULED_TASK_CRADLE: 'Malicious Scheduled Task Persistence',
    SCHEDULED_TASK_CREATED: 'Scheduled Task Created',
    SERVICE_SUSPICIOUS_PATH: 'Suspicious Service Installation',
    AUDIT_LOG_CLEARED: 'Security Log Tampering',
    NTDS_ACCESS: 'Active Directory Credential Dump',
    SAM_ACCESS: 'SAM Database Access',
    LSASS_DUMP_RUNDLL32: 'LSASS Memory Dump via LOLBin',
    MIMIKATZ_DETECTED: 'Mimikatz Credential Dumping',
    ACCOUNT_CREATED_SUSPICIOUS: 'Suspicious Account Creation',
    ACCOUNT_CREATED: 'New Account Creation',
    ACTIVE_CAMPAIGN: 'Multi-Asset Coordinated Attack',
    REPEATED_INDICATOR: 'Repeated Malicious Indicator',
    ENRICHMENT_CONFIRMED_MALICIOUS: 'Connection from Known Malicious IP',
    ENRICHMENT_SUSPICIOUS: 'Connection from Suspicious IP',
    ENRICHMENT_CLEAN: 'Network Connection — Clean Source',
  }

  const topBehavioral = sorted.find(s => s.category === 'behavioral' || s.category === 'frequency')
  const classification = topBehavioral ? (classificationMap[topBehavioral.rule] ?? 'UNKNOWN') : (classificationMap[dominant.rule] ?? 'UNKNOWN')
  const deterministicMitre = sorted.find(s => s.mitre)?.mitre ?? null

  const top3 = sorted.slice(0, 3)
  const baseConfidence = top3.reduce((sum, s) => sum + s.confidence * s.weight, 0) / Math.max(top3.reduce((sum, s) => sum + s.weight, 0), 1)
  const campaignBonus = signals.some(s => s.rule === 'ACTIVE_CAMPAIGN') ? 10 : 0
  const unknownPenalty = classification === 'UNKNOWN' ? -20 : 0
  const parseBonus = parseQuality === 'structured' ? 10 : parseQuality === 'partial' ? 0 : -10
  const finalConfidence = Math.round(Math.max(0, Math.min(100, baseConfidence + parseBonus + campaignBonus + unknownPenalty)))

  const decision_trace = [
    { type: 'dominant', label: `${dominant.label}`, category: dominant.category, weight: dominant.weight, confidence: dominant.confidence, rule: dominant.rule },
    { type: 'severity', label: `${finalSeverity} across ${signals.length} signals`, value: finalSeverity },
    { type: 'classification', label: classification, rule: topBehavioral?.rule ?? dominant.rule },
    { type: 'asset', label: `Critical: ${assetIsCritical}`, value: assetIsCritical },
    { type: 'confidence', label: `${finalConfidence}`, base: Math.round(baseConfidence), campaignBonus, unknownPenalty, parseBonus },
    ...sorted.slice(1).map(s => ({ type: 'supporting', label: s.label, severity: s.severity, category: s.category, rule: s.rule }))
  ]

  return {
    severity:          finalSeverity,
    classification,
    confidence:        finalConfidence,
    asset_is_critical: assetIsCritical,
    affected_asset:    null,
    evidence:          [...new Set((signals ?? []).flatMap(s => s.evidence ?? []))].slice(0, 8),
    decision_trace:    decision_trace ?? [],
    signals:           signals ?? [],
    deterministicMitre,
  }
}

function buildNarratorPrompt(sanitizedAlert, parsedContext, enrichmentJudgment, redisContext, isActiveCampaign, uniqueAssetCount, frequencyMultiplier, finalVerdict) {
  return `You are ARBITER's Narrator Layer. A deterministic engine has already produced the final verdict below.

YOUR ROLE IS STRICTLY LIMITED TO:
1. Mapping the behavior to a specific MITRE ATT&CK technique and subtechnique
2. Writing a 4-sentence reasoning explanation
3. Writing 5 specific executable recommendations
4. Populating the indicators field with technical facts

YOU MUST NOT override: severity (${finalVerdict.severity}), classification (${finalVerdict.classification}), confidence (${finalVerdict.confidence}), asset_is_critical (${finalVerdict.asset_is_critical})

═══ FINAL VERDICT (DETERMINISTIC — DO NOT OVERRIDE) ═══
severity: ${finalVerdict.severity}
classification: ${finalVerdict.classification}
confidence: ${finalVerdict.confidence}
asset_is_critical: ${finalVerdict.asset_is_critical}
decision_trace: ${finalVerdict.decision_trace.slice(0,3).join(' | ')}

═══ STRUCTURED ALERT DATA ═══
ALERT TYPE: ${parsedContext.alertType ?? 'Unknown'}
RAW ALERT:
${sanitizedAlert}

PRE-PARSED FIELDS:
${parsedContext.fields || 'No structured fields extracted'}

ENRICHMENT JUDGMENT:
${enrichmentJudgment.summary}
VERDICT: ${enrichmentJudgment.judgment}
blockRecommendationAllowed: ${enrichmentJudgment.blockRecommendationAllowed}

${redisContext ? `TEMPORAL CORRELATION:\n${redisContext}\n${isActiveCampaign ? `ACTIVE CAMPAIGN: ${frequencyMultiplier} hits across ${uniqueAssetCount} unique assets.` : ''}` : ''}

Return ONLY a JSON object. No markdown, no backticks, no preamble:
{
  "indicators": string[] (3-8 technical facts from the alert — list EventCodes, binary names, arguments, asset names, timestamps),
  "tactic": string (MITRE tactic — must match mitre_tactic exactly),
  "mitre_id": string (MUST be a real existing MITRE ATT&CK subtechnique ID — examples: T1053.005 for scheduled tasks, T1059.001 for PowerShell, T1110.001 for brute force, T1021.002 for SMB lateral movement, T1566.001 for spearphishing attachment, T1078 for valid accounts, T1070.001 for log clearing, T1003.001 for lsass dump),
  "mitre_name": string (official MITRE name for the mitre_id),
  "mitre_tactic": string (must match tactic exactly),
  "recommendations": string[] (exactly 5 — each must be an executable command using real field values: Run: Get-WinEvent / net user / schtasks / sc stop / Isolate / Block / Collect memory image),
  "recommendation_provenance": string[] (exactly 5 — each: enrichment_confirmed|behavioral_heuristic|account_action|forensic|known_good_override),
  "reasoning": string (exactly 4 sentences as a plain string — not an object, not an array: sentence 1=what technique/binary/event, sentence 2=enrichment or behavioral driver, sentence 3=which rule triggered severity, sentence 4=most urgent action with specific asset/account)
}

CRITICAL RULES — VIOLATIONS WILL BE CORRECTED BY THE DETERMINISTIC ENGINE:
- Return EXACTLY 5 recommendations. Not 4, not 6. Exactly 5.
- Every recommendation MUST start with one of: "Run:", "Isolate", "Block", "Collect", "Disable", "Remove", "Terminate"
- Every recommendation MUST name a specific hostname, username, or IP from the alert data above
- Generic recommendations like "Contact IT", "Follow security policies", "Monitor the situation" are REJECTED
- NEVER block RFC 1918 addresses (10.x, 172.16-31.x, 192.168.x)
- NEVER suggest wevtutil clear-log, del *.evtx, Clear-EventLog
- reasoning MUST be a plain string — never an object or array
- mitre_id MUST be a real MITRE ATT&CK subtechnique ID

MANDATORY RECOMMENDATION FORMAT:
01: CONTAIN  — Isolate or block the immediate threat
02: INVESTIGATE — Run a specific log query with Get-WinEvent or equivalent
03: VALIDATE — Check account status with net user or verify process with tasklist
04: HARDEN  — Remove persistence (schtasks /delete, sc stop, net user /delete)
05: FORENSIC — Collect memory image or preserve evidence

Use real values from the alert. Replace [HOSTNAME], [USERNAME], [IP] with actual values from the structured data above.`
}

// ── IP ENRICHMENT ─────────────────────────────────────────────────────────────
async function enrichIP(ip) {
  const results = {}

  const [abuseResult, vtResult, otxResult] = await Promise.allSettled([
    fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
      { headers: { 'Key': process.env.ABUSEIPDB_API_KEY, 'Accept': 'application/json' } }
    ).then(r => r.json()),

    fetch(
      `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
      { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } }
    ).then(r => r.json()),

    fetch(
      `https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`,
      { headers: { 'X-OTX-API-KEY': process.env.OTX_API_KEY } }
    ).then(r => r.json()),
  ])

  if (abuseResult.status === 'fulfilled' && !abuseResult.value?.errors) {
    const d = abuseResult.value?.data
    results.abuseipdb = {
      score:        d?.abuseConfidenceScore ?? 0,
      country:      d?.countryCode ?? null,
      isp:          d?.isp ?? null,
      totalReports: d?.totalReports ?? 0,
      domain:       d?.domain ?? null,
      usageType:    d?.usageType ?? null,
      isTorNode:    d?.isTor ?? false,
    }
  } else { results.abuseipdb = null }

  if (vtResult.status === 'fulfilled' && !vtResult.value?.error) {
    const attrs = vtResult.value?.data?.attributes
    const stats = attrs?.last_analysis_stats ?? {}
    results.virustotal = {
      malicious:  stats.malicious  ?? 0,
      suspicious: stats.suspicious ?? 0,
      total:      Object.values(stats).reduce((a, b) => a + b, 0),
      country:    attrs?.country   ?? null,
      asn:        attrs?.asn       ?? null,
      asOwner:    attrs?.as_owner  ?? null,
      network:    attrs?.network   ?? null,
    }
  } else { results.virustotal = null }

  if (otxResult.status === 'fulfilled') {
    const d = otxResult.value
    results.otx = {
      pulseCount:    d?.pulse_info?.count ?? 0,
      tags:          d?.tags ?? [],
      malwareFamily: d?.pulse_info?.pulses?.[0]?.malware_families?.[0]?.display_name ?? null,
    }
  } else { results.otx = null }

  return results
}

// ── ENRICHMENT JUDGMENT ENGINE ────────────────────────────────────────────────
function buildEnrichmentJudgment(enrichment, ips, frequencyMultiplier = 0) {
  if (!ips.length) {
    return {
      summary: 'No public IPs detected. Analysis based on behavioral indicators only.',
      judgment: 'NO_IP',
      blockRecommendationAllowed: false,
      confidenceModifier: 0,
    }
  }

  const ipJudgments = ips.map(ip => {
    const d = enrichment[ip]
    if (!d) return { ip, verdict: 'UNAVAILABLE', signals: [], modifier: 0, blockAllowed: false, threatScore: 0 }

    const signals = []
    let threatScore = 0
    let blockAllowed = false

    if (d.abuseipdb) {
      const score = d.abuseipdb.score
      if (d.abuseipdb.isTorNode) {
        signals.push(`CONFIRMED TOR EXIT NODE — anonymization active, attacker concealing origin`)
        threatScore += 40
        blockAllowed = true
      }
      if (score >= 80) {
        signals.push(`AbuseIPDB CONFIRMED MALICIOUS: ${score}/100 (${d.abuseipdb.totalReports} reports) via "${d.abuseipdb.isp}" AS`)
        threatScore += 35
        blockAllowed = true
      } else if (score >= 40) {
        signals.push(`AbuseIPDB SUSPICIOUS: ${score}/100 — do not lower severity based on this alone`)
        threatScore += 15
      } else if (score === 0 && d.abuseipdb.totalReports === 0) {
        signals.push(`AbuseIPDB CLEAN: score=0, zero reports — residential/commercial ISP "${d.abuseipdb.isp}"`)
        threatScore -= 5
      }
    }

    if (d.virustotal) {
      const mal = d.virustotal.malicious
      const total = d.virustotal.total
      if (mal >= 10) {
        signals.push(`VirusTotal CONFIRMED: ${mal}/${total} engines flagged — cross-validated threat`)
        threatScore += 30
        blockAllowed = true
      } else if (mal >= 3) {
        signals.push(`VirusTotal SUSPICIOUS: ${mal}/${total} engines flagged — corroborating signal`)
        threatScore += 15
      } else if (mal === 1) {
        signals.push(`VirusTotal WEAK SIGNAL: 1/${total} engine flagged — single detection, low weight`)
        threatScore += 3
      } else if (mal === 0) {
        signals.push(`VirusTotal CLEAN: 0/${total} engines — not a known malicious IP`)
        threatScore -= 3
      }
    }

    if (d.otx) {
      const pulses = d.otx.pulseCount
      if (d.otx.malwareFamily) {
        signals.push(`OTX MALWARE CONFIRMED: "${d.otx.malwareFamily}" — ${pulses} threat intelligence pulses`)
        threatScore += 35
        blockAllowed = true
      } else if (pulses > 20) {
        signals.push(`OTX HIGH ACTIVITY: ${pulses} pulses — known threat actor infrastructure`)
        threatScore += 25
        blockAllowed = true
      } else if (pulses > 5) {
        signals.push(`OTX MODERATE: ${pulses} pulses — suspicious but no malware family confirmed`)
        threatScore += 10
      } else if (pulses > 0) {
        signals.push(`OTX LOW: ${pulses} pulses — weak signal, mixed context`)
        threatScore += 3
      } else {
        signals.push(`OTX CLEAN: 0 pulses — not in any known threat intelligence feed`)
        threatScore -= 3
      }
    }

    let verdict, modifier
    if (threatScore >= 60)      { verdict = 'CONFIRMED_MALICIOUS'; modifier = +15 }
    else if (threatScore >= 25) { verdict = 'SUSPICIOUS';          modifier = +5  }
    else if (threatScore >= 5)  { verdict = 'MIXED_SIGNALS';       modifier = -10 }
    else                        { verdict = 'CLEAN';               modifier = -20 }

    const hasConflict = d.abuseipdb && d.virustotal && d.otx &&
      ((d.abuseipdb.score >= 80 && d.virustotal.malicious === 0 && d.otx.pulseCount === 0) ||
       (d.abuseipdb.score === 0 && d.virustotal.malicious >= 10) ||
       (d.abuseipdb.score === 0 && d.otx.pulseCount > 20 && d.virustotal.malicious === 0))

    if (hasConflict) {
      signals.push(`CONFLICTING SOURCES: sources disagree — treat as SUSPICIOUS, do not escalate to CRITICAL on enrichment alone`)
      modifier = -5
    }

    return { ip, verdict, signals, modifier, blockAllowed, threatScore, raw: { abuseipdb: d.abuseipdb, virustotal: d.virustotal, otx: d.otx } }
  })

  const dominantVerdict = ipJudgments.reduce((acc, j) => {
    const order = ['CONFIRMED_MALICIOUS', 'SUSPICIOUS', 'MIXED_SIGNALS', 'CLEAN', 'UNAVAILABLE']
    return order.indexOf(j.verdict) < order.indexOf(acc) ? j.verdict : acc
  }, 'UNAVAILABLE')

  const blockAllowed   = ipJudgments.some(j => j.blockAllowed)
  const totalModifier  = ipJudgments.reduce((sum, j) => sum + j.modifier, 0)
  const summaryLines   = ipJudgments.map(j => [`IP ${j.ip} — VERDICT: ${j.verdict} (threat score: ${j.threatScore})`, ...j.signals.map(s => `  • ${s}`)].join('\n'))
  const frequencyBonus = frequencyMultiplier >= 3 ? 20 : frequencyMultiplier >= 2 ? 10 : 0
  const frequencyNote  = frequencyMultiplier >= 3 ? `\nFREQUENCY ALERT: This indicator has appeared ${frequencyMultiplier}× across sessions — automatic severity escalation applied.` : ''

  return {
    summary:                   summaryLines.join('\n\n') + frequencyNote,
    judgment:                  frequencyMultiplier >= 3 ? 'CONFIRMED_MALICIOUS' : dominantVerdict,
    blockRecommendationAllowed: blockAllowed || frequencyMultiplier >= 3,
    confidenceModifier:        Math.max(-25, Math.min(+20, totalModifier + frequencyBonus)),
    ipJudgments,
  }
}

// ── SYSTEM PROMPT ─────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are ARBITER — a senior detection engineering triage engine. You reason in two steps: enumerate technical facts, then judge. You never skip to judgment without enumeration.

═══ ABSOLUTE OUTPUT RULES ═══
1. "tactic" and "mitre_tactic" MUST be identical strings — copy one from the other.
2. "classification" MUST be a human-readable technique name. NEVER put a MITRE ID (T1xxx) in classification.
3. "mitre_id" MUST be the most specific subtechnique: T1003.003 not T1003. T1021.002 not T1021.
4. NEVER recommend blocking an RFC 1918 address (10.x, 172.16-31.x, 192.168.x).
5. NEVER suggest commands that destroy evidence (wevtutil clear-log, del *.evtx, Clear-EventLog).
6. PROCESS EVERY EVENT IN THE ALERT. If the alert contains multiple EventCodes, you must enumerate all of them in Step 1 and let the highest-severity event drive the final verdict.

═══ STEP 1 — MANDATORY FACT ENUMERATION ═══
Before classifying, populate the "indicators" field with these facts in order:
1. List every distinct EventCode present in this alert and what each represents mechanically.
2. For each process execution event: what binary, what arguments, is this canonical or anomalous use?
3. What is the parent-child process relationship? Is spawning winword→mshta, excel→powershell, etc. suspicious?
4. Are there multiple assets in this alert? List each one — first asset, second asset, destination asset.
5. What are the timestamps? Calculate time gaps between events. Events within 5 minutes = coordinated chain.
6. What does the enrichment verdict say?
7. Is there a SEQUENCE here — initial compromise → persistence → lateral movement?

═══ MULTI-EVENT CHAIN DETECTION ═══
When an alert contains multiple EventCodes, apply these escalation rules:

SEQUENCE PATTERNS — escalate to CRITICAL if ANY of these chains appear:
  - 4688 (process/LOLBin) → 4698 (scheduled task) = execution + persistence chain → CRITICAL
  - 4688 (LOLBin) → 4624 (successful logon on different asset) = execution + lateral movement → CRITICAL
  - 4698 (scheduled task) → 4624 (different WorkstationName) = persistence + lateral movement → CRITICAL
  - ANY three events within 10 minutes spanning two different assets = CRITICAL
  - 4688 (anomalous) + 4698 (malicious TaskContent) + 4624 = full kill chain → CRITICAL, confidence ≥ 95

TIME GAP ANALYSIS:
  - Events within 2 minutes of each other = automated/scripted attack, raise confidence by 15
  - Events spanning different WorkstationNames = lateral movement confirmed
  - If EventCode 4624 appears with a DIFFERENT WorkstationName than 4688/4698 events = lateral movement in progress

AFFECTED ASSET in multi-event alerts:
  - Use the FIRST compromised asset as affected_asset
  - Note the lateral movement destination in reasoning ("attacker moved to CORP-SRV-12 at 23:51")
  - NEVER ignore a 4624 that appears after a 4688/4698 sequence on a different host

PARENT PROCESS ANOMALIES (always CRITICAL or HIGH):
  - winword.exe / excel.exe / powerpnt.exe spawning any shell or LOLBin = macro dropper, CRITICAL
  - outlook.exe spawning any process = phishing delivery, CRITICAL
  - browser spawning mshta/wscript/cscript = drive-by download, HIGH
  - explorer.exe spawning encoded powershell = user-executed payload, HIGH

═══ LOLBIN BEHAVIORAL MATRIX ═══

mshta.exe:
  CANONICAL: launching .HTA applications from local disk
  ANOMALOUS: executing remote HTTP/HTTPS URL, inline script, spawning cmd/powershell
  If spawned from Office app + remote URL: CRITICAL (macro dropper confirmed)
  If remote URL but unknown parent: HIGH minimum

certutil.exe:
  CANONICAL: certificate store management, Base64 encode/decode of certificates
  ANOMALOUS: -urlcache, -split, -f with remote URL, any .exe/.dll/.ps1 output path
  ANOMALOUS output paths: C:\Users\Public\, C:\Windows\Temp\, C:\ProgramData\
  MINIMUM HIGH regardless of enrichment

regsvr32.exe:
  CANONICAL: COM DLL registration from System32 or Program Files
  ANOMALOUS: /i: with HTTP/HTTPS URL, .sct files, scrobj.dll with remote path
  T1218.010 — MINIMUM HIGH

powershell.exe:
  CANONICAL: administrative scripting
  ANOMALOUS: -enc/-encodedCommand (always flag), IEX+DownloadString (CRITICAL), Invoke-Mimikatz (CRITICAL), -WindowStyle Hidden + network = HIGH

rundll32.exe / wscript.exe / cscript.exe:
  ANOMALOUS: executing from Temp/Public/AppData, loading remote content, spawning shells
  MINIMUM HIGH

GREY ZONE RULE:
  LOLBin used anomalously + clean IP enrichment: MEDIUM minimum, note "behavioral anomaly primary signal, clean enrichment does not excuse anomalous use"

═══ EVENT ID → MITRE MAPPING ═══

4625 (Failed Logon) → "Credential Access"
  Count ≤ 3 + internal IP = LOW (user error)
  Count > 5 + same username + external IP = T1110.001
  Count > 5 + rotating usernames = T1110.003
  Count > 20 + DC = CRITICAL

4624 (Successful Logon) → "Initial Access" or "Lateral Movement"
  After brute force sequence = CRITICAL
  Different WorkstationName than prior events in same alert = T1021 Lateral Movement
  External IP + NTLM = T1078

4688 (Process Created) → tactic from LOLBin matrix above
  Office app as parent → LOLBin = T1566 Phishing + technique
  PsExec/PSEXESVC = T1021.002
  Plaintext password in CommandLine = CRITICAL always

4663 / 4656 (Object Access) → "Credential Access"
  ntds.dit = T1003.003, SAM = T1003.002, lsass = T1003.001

4698 / 4702 (Scheduled Task) → "Persistence", ALWAYS T1053.005
  EventCode 4698 = T1053.005 regardless of TaskContent payload
  TaskContent with IEX/DownloadString/-enc/certutil = CRITICAL
  TaskContent with defrag/sfc/cleanmgr + admin user + business hours = LOW

4720 + 4732 → "Persistence", T1136.001 + T1098
  Username contains backdoor/hack/persist/0day = CRITICAL

4697 / 7045 → "Persistence", T1543.003
  ServiceFileName in Temp/Users/ProgramData = CRITICAL
  ServiceName mimics legitimate service = add T1036 masquerading note

1102 / 4719 → "Defense Evasion", T1070.001
  On DC = CRITICAL. Elsewhere = HIGH minimum.

4104 → varies by content
  Invoke-Mimikatz/BloodHound = "Credential Access", CRITICAL
  IEX + remote URL = "Execution", CRITICAL

═══ SEVERITY RULES ═══

CRITICAL — any one sufficient:
  Multi-event chain spanning two assets (see chain detection above)
  Office app spawning LOLBin with remote URL
  DC targeted
  ntds.dit/SAM/lsass accessed
  Audit log cleared
  Plaintext credentials in CommandLine
  OTX malware family confirmed
  Scheduled task with download cradle

HIGH — any one sufficient:
  Single LOLBin anomalous use without chain
  Service account targeted
  Confirmed Tor node
  AbuseIPDB ≥ 80
  Binary executed from Temp/Public/AppData
  Encoded PowerShell

MEDIUM:
  External IP + single event + mixed enrichment
  Discovery commands in isolation
  LOLBin + clean enrichment (grey zone)

LOW:
  Count ≤ 3 + internal IP + standard user + no other indicators
  Known maintenance binary + admin + business hours

═══ ENRICHMENT JUDGMENT FRAMEWORK ═══
Read the pre-computed VERDICT field:
  CONFIRMED_MALICIOUS → may recommend IP block, raise severity
  SUSPICIOUS → corroborating signal, do not auto-escalate
  MIXED_SIGNALS → note conflict, do not escalate on enrichment alone
  CLEAN → consider benign explanation, reduce confidence 15-20 pts
  NO_IP → never recommend IP blocking, focus on host/account actions

Apply the confidenceModifier: base confidence ± modifier = final confidence.
When blockRecommendationAllowed = false: ZERO IP blocking recommendations.

═══ ASSET CRITICALITY ═══
TRUE: DC/-DC-/PDC/BDC/ADC, SQL/DB/ORA, BACKUP/BKP/VEEAM, EXCHANGE/MAIL, or ntds.dit/SAM/krbtgt targeted.
FALSE: WKS/LAPTOP/DESKTOP/PC/SRV alone.

═══ RECOMMENDATION ENFORCEMENT ═══

HARD RULES:
1. Never block RFC 1918 addresses.
2. Never suggest evidence-destroying commands.
3. Every recommendation must name a specific indicator (IP, username, hostname, command, taskname).
4. Starting a recommendation with ONLY "Investigate", "Review", "Monitor", "Check", "Verify", or "Contain" is REJECTED unless followed immediately by a specific executable action.
5. Order: CONTAIN → INVESTIGATE → VALIDATE → HARDEN → DOCUMENT.
6. For multi-event alerts: at least one recommendation must address EACH compromised asset.

MANDATORY COMMAND FORMATS — you MUST use these exact patterns with real values substituted:

Account actions:
  "Run: net user [USERNAME] /domain /active:no — disable [USERNAME] pending investigation"
  "Run: net user [USERNAME] /delete — remove unauthorized account created by [CREATOR]"
  "Run: net localgroup Administrators [USERNAME] /delete — remove from admin group"

Service/task actions:
  "Run: schtasks /delete /tn '[TASKNAME]' /f on [HOSTNAME] — remove malicious persistence"
  "Run: sc stop [SERVICENAME] && sc delete [SERVICENAME] on [HOSTNAME]"

Investigation:
  "Run: Get-WinEvent -FilterHashtable @{LogName='Security'; Id=[ID]} -ComputerName [HOST] | Select -First 50"
  "Run: schtasks /query /fo LIST /v on [HOST] — audit all scheduled tasks"

Network:
  "Block [IP]/32 at perimeter firewall — AbuseIPDB [SCORE]/100, [REPORTS] reports"
  "Isolate [HOSTNAME] from network — active compromise, lateral movement to [DEST_HOST] detected"

Forensic:
  "Collect memory image from [HOSTNAME] before shutdown — volatile evidence preservation"
  "Run: Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ComputerName [DEST_HOST] | Where {$_.TimeCreated -gt '[TIMESTAMP]'}"

═══ REASONING STANDARDS ═══
4 sentences exactly:
  1. What technique was used and which binary/account/event code
  2. What the enrichment verdict says, or what behavioral indicators drive severity without enrichment
  3. What specific rule or chain triggered the severity level (name the rule)
  4. The single most urgent action right now with the specific hostname or account

═══ OUTPUT SCHEMA ═══
Single valid JSON object. No markdown, no backticks, no preamble, no text after closing brace.

{
  "indicators": string[] (3–8 items — enumerate ALL EventCodes present, process chain, assets, time gaps, enrichment),
  "classification": string (descriptive name only, NEVER a MITRE ID),
  "tactic": string (MUST equal mitre_tactic exactly),
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence": number (base ± enrichment modifier),
  "mitre_id": string (most specific subtechnique),
  "mitre_name": string,
  "mitre_tactic": string (MUST equal tactic exactly),
  "affected_asset": string (first compromised asset),
  "asset_is_critical": boolean,
  "recommendations": string[] (exactly 5 — each must contain an executable command or specific named action, generic openers alone are REJECTED),
  "recommendation_provenance": string[] (exactly 5 — each one of: "enrichment_confirmed" | "behavioral_heuristic" | "account_action" | "forensic" | "known_good_override"),
  Provenance guide: "enrichment_confirmed" = recommendation driven by AbuseIPDB/VT/OTX data. "behavioral_heuristic" = driven by LOLBin matrix or process chain. "account_action" = disabling/deleting an account. "forensic" = log query or evidence collection. "known_good_override" = ONLY use when recommending NO action because pattern is benign.
  "reasoning": string (exactly 4 sentences per the standards above),
  "evidence": string[] (3–6 raw FIELD=VALUE pairs from the alert that drove the verdict)
}`

// ── MITRE NAME LOOKUP ─────────────────────────────────────────────────────────
function getMitreName(id) {
  const names = {
    'T1110.001': 'Brute Force: Password Guessing',
    'T1110': 'Brute Force',
    'T1105': 'Ingress Tool Transfer',
    'T1218.005': 'System Binary Proxy Execution: Mshta',
    'T1566.001': 'Phishing: Spearphishing Attachment',
    'T1204.002': 'User Execution: Malicious File',
    'T1059.001': 'Command and Scripting Interpreter: PowerShell',
    'T1053.005': 'Scheduled Task/Job: Scheduled Task',
    'T1543.003': 'Create or Modify System Process: Windows Service',
    'T1070.001': 'Indicator Removal: Clear Windows Event Logs',
    'T1003.001': 'OS Credential Dumping: LSASS Memory',
    'T1003.003': 'OS Credential Dumping: NTDS',
    'T1003.002': 'OS Credential Dumping: Security Account Manager',
    'T1078': 'Valid Accounts',
    'T1071.001': 'Application Layer Protocol: Web Protocols',
    'T1136.001': 'Create Account: Local Account',
  }
  return names[id] ?? id
}

function getClassificationMitre(classification) {
  const map = {
    'Brute Force Attack':                    { id: 'T1110.001', tactic: 'Credential Access' },
    'Password Spraying':                     { id: 'T1110.003', tactic: 'Credential Access' },
    'Failed Logon':                          { id: 'T1110',     tactic: 'Credential Access' },
    'Malicious File Download via LOLBin':    { id: 'T1105',     tactic: 'Command and Control' },
    'LOLBin Staging to Suspicious Path':     { id: 'T1105',     tactic: 'Command and Control' },
    'Remote Script Execution via mshta':     { id: 'T1218.005', tactic: 'Defense Evasion' },
    'Macro-based Dropper Execution':         { id: 'T1204.002', tactic: 'Execution' },
    'Encoded PowerShell Execution':          { id: 'T1059.001', tactic: 'Execution' },
    'Malicious Scheduled Task Persistence':  { id: 'T1053.005', tactic: 'Persistence' },
    'Scheduled Task Created':                { id: 'T1053.005', tactic: 'Persistence' },
    'Suspicious Service Installation':       { id: 'T1543.003', tactic: 'Persistence' },
    'Security Log Tampering':                { id: 'T1070.001', tactic: 'Defense Evasion' },
    'Active Directory Credential Dump':      { id: 'T1003.003', tactic: 'Credential Access' },
    'SAM Database Access':                   { id: 'T1003.002', tactic: 'Credential Access' },
    'LSASS Memory Dump via LOLBin':          { id: 'T1003.001', tactic: 'Credential Access' },
    'Mimikatz Credential Dumping':           { id: 'T1003.001', tactic: 'Credential Access' },
    'Multi-Asset Coordinated Attack':        { id: 'T1078',     tactic: 'Defense Evasion' },
    'Repeated Malicious Indicator':          { id: 'T1078',     tactic: 'Defense Evasion' },
    'Connection from Known Malicious IP':    { id: 'T1071.001', tactic: 'Command and Control' },
    'Suspicious Account Creation':           { id: 'T1136.001', tactic: 'Persistence' },
    'New Account Creation':                  { id: 'T1136.001', tactic: 'Persistence' },
  }
  return map[classification] ?? null
}

// ── STREAMING ROUTE HANDLER ───────────────────────────────────────────────────
export async function POST(request) {
  const startTime = Date.now()

  const encoder = new TextEncoder()

  function send(controller, event, data) {
    controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`))
  }

  const stream = new ReadableStream({
    async start(controller) {
      try {
        const { alertText, sessionId } = await request.json()
        const safeSessionId = (sessionId ?? 'default').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64)

        if (!alertText?.trim() || alertText.trim().length < 10) {
          send(controller, 'error', { message: 'Alert text is too short.' })
          controller.close()
          return
        }

        const parsedAlert   = parseAlert(alertText)

        // ── ACS NORMALIZATION (feature/acs-architecture) ──────────────────────
        // Runs alongside existing pipeline — does not yet replace it.
        // Will progressively take over detection in future iterations.
        let acsObject = null
        try {
          const { normalize } = await import('./normalizer.js')
          acsObject = normalize(alertText, parsedAlert)
        } catch (acsErr) {
          console.error('[ARBITER/ACS] Normalization failed:', acsErr.message)
          acsObject = null
        }

        const sanitizedAlert = sanitizeAlertText(
          alertText.length > 3000 ? alertText.slice(0, 3000) + '\n[TRUNCATED]' : alertText
        )
        const ips = extractIPs(alertText)

        // ── PHASE 1: ENRICHMENT ──────────────────────────────────────────────
        send(controller, 'status', { phase: 'enriching', message: 'Enriching threat intelligence...' })

        const enrichment = {}
        if (ips.length > 0) {
          const enrichResults = await Promise.all(ips.map(ip => enrichIP(ip)))
          ips.forEach((ip, i) => { enrichment[ip] = enrichResults[i] })
        }

        // Stream enrichment immediately
        send(controller, 'enrichment', { enrichment, ips })

        // Warn analyst if enrichment sources are unavailable
        const enrichmentHealth = getEnrichmentHealth(enrichment, ips)
        if (enrichmentHealth.failed.length > 0) {
          send(controller, 'warning', {
            message: `Enrichment incomplete: ${enrichmentHealth.failed.join(', ')} unavailable. Confidence may be reduced.`,
            failedSources: enrichmentHealth.failed,
          })
        }

        // ── REDIS: READ HISTORICAL CONTEXT ───────────────────────────────────
        const normalizedUsername = parsedAlert.username // already normalized in parseAlert

        const redisContextResult = await getRedisContext(ips, normalizedUsername, safeSessionId)
        const redisHits    = redisContextResult?.hits ?? null
        const redisPatterns = redisContextResult?.patterns ?? []
        const redisContext = buildRedisContextSummary(redisHits)
        const isCorrelated = !!(redisHits?.length)

        if (isCorrelated) {
          send(controller, 'correlation', { hits: redisHits, summary: redisContext, patterns: redisPatterns })
        }

        // ── PHASE 2: LLM TRIAGE WITH FULL ENRICHMENT CONTEXT ────────────────
        send(controller, 'status', { phase: 'analyzing', message: 'ARBITER is analyzing your alert...' })

        const frequencyMultiplier = redisHits?.reduce((max, h) => Math.max(max, h.count ?? 0), 0) ?? 0
        const uniqueAssetCount    = (() => {
          if (!redisHits?.length) return 0
          const set = new Set()
          redisHits.forEach(h => (h.assets ?? []).filter(Boolean).forEach(a => set.add(a)))
          return set.size
        })()
        const maxRedisCount       = redisHits?.reduce((max, h) => Math.max(max, h.count ?? 0), 0) ?? 0
        const isActiveCampaign    = (frequencyMultiplier >= 2 && uniqueAssetCount >= 2) || maxRedisCount >= 3
        const enrichmentJudgment  = buildEnrichmentJudgment(enrichment, ips, frequencyMultiplier)

        const signals      = getSignals(parsedAlert, enrichmentJudgment, redisHits)
        let finalVerdict
        try {
          finalVerdict = aggregateSignals(signals, parsedAlert.parseQuality)
        } catch (engineErr) {
          console.error('[ARBITER] Decision engine error:', engineErr)
          finalVerdict = {
            severity: 'UNKNOWN',
            classification: 'UNKNOWN',
            confidence: 0,
            asset_is_critical: false,
            affected_asset: null,
            evidence: [],
            decision_trace: [{ type: 'error', label: 'Decision engine failed — manual review required' }],
            signals: [],
            deterministicMitre: null,
          }
        }
        if (parsedAlert.parseQuality === 'partial') {
          finalVerdict.confidence = Math.max(0, finalVerdict.confidence - 25)
          finalVerdict.decision_trace.push({ type: 'penalty', label: 'Parse quality PARTIAL — confidence reduced by 25', value: -25 })
        }
        const failedSourceCount = enrichmentHealth.noIp ? 0 : (enrichmentHealth.failed ?? []).length
        if (failedSourceCount > 0) {
          const enrichmentPenalty = failedSourceCount * 8
          finalVerdict.confidence = Math.max(0, finalVerdict.confidence - enrichmentPenalty)
          finalVerdict.decision_trace.push({
            type: 'penalty',
            label: `Enrichment failed: ${(enrichmentHealth.failed ?? []).join(', ')} — confidence -${enrichmentPenalty}`,
            value: -enrichmentPenalty,
            sources: enrichmentHealth.failed ?? [],
          })
        }

        const parsedContext = Object.entries(parsedAlert)
          .filter(([_, v]) => v !== null)
          .map(([k, v]) => `${k}: ${v}`)
          .join('\n')

        const groqStream = await groq.chat.completions.create({
          model:       'llama-3.3-70b-versatile',
          temperature: 0.1,
          max_tokens:  2000,
          stream:      false,
          messages: [
            {
              role: 'user',
              content: buildNarratorPrompt(
                sanitizedAlert,
                { alertType: parsedAlert.alertType, fields: parsedContext },
                enrichmentJudgment,
                redisContext,
                isActiveCampaign,
                uniqueAssetCount,
                frequencyMultiplier,
                finalVerdict
              )
            }
          ]
        })

        const raw = groqStream.choices[0]?.message?.content ?? ''

        const narratorOutput = (() => {
          try {
            const jsonMatch = raw.match(/\{[\s\S]*\}/)
            if (!jsonMatch) return null
            return JSON.parse(jsonMatch[0])
          } catch { return null }
        })()


        const narratorFallback = {
          indicators: finalVerdict.decision_trace.slice(0, 5).map(d => typeof d === 'object' ? d.label : d),
          tactic: (() => {
            const mitreToTactic = {
              'T1110.001': 'Credential Access', 'T1110': 'Credential Access',
              'T1105': 'Command and Control', 'T1218.005': 'Defense Evasion',
              'T1204.002': 'Execution', 'T1059.001': 'Execution',
              'T1053.005': 'Persistence', 'T1543.003': 'Persistence',
              'T1070.001': 'Defense Evasion', 'T1003.003': 'Credential Access',
              'T1003.002': 'Credential Access', 'T1078': 'Defense Evasion',
              'T1566.001': 'Initial Access',
            }
            return mitreToTactic[finalVerdict.deterministicMitre] ?? 'Unknown'
          })(),
          mitre_id: finalVerdict.deterministicMitre ?? 'T0000',
          mitre_name: finalVerdict.deterministicMitre ? getMitreName(finalVerdict.deterministicMitre) : finalVerdict.classification,
          mitre_tactic: (() => {
            const mitreToTactic = {
              'T1110.001': 'Credential Access', 'T1110': 'Credential Access',
              'T1105': 'Command and Control', 'T1218.005': 'Defense Evasion',
              'T1204.002': 'Execution', 'T1059.001': 'Execution',
              'T1053.005': 'Persistence', 'T1543.003': 'Persistence',
              'T1070.001': 'Defense Evasion', 'T1003.003': 'Credential Access',
              'T1003.002': 'Credential Access', 'T1078': 'Defense Evasion',
              'T1566.001': 'Initial Access',
            }
            return mitreToTactic[finalVerdict.deterministicMitre] ?? 'Unknown'
          })(),
          recommendations: [
            `Investigate ${parsedAlert.asset ?? 'affected asset'} for suspicious activity`,
            `Review logs for ${parsedAlert.username ?? 'involved accounts'}`,
            `Check network connections from ${parsedAlert.asset ?? 'affected host'}`,
            'Escalate to senior analyst if indicators persist',
            'Document findings and preserve evidence before remediation'
          ],
          recommendation_provenance: ['behavioral_heuristic','forensic','forensic','behavioral_heuristic','forensic'],
          reasoning: `Deterministic engine classified this alert as ${finalVerdict.classification} with ${finalVerdict.severity} severity. ${typeof finalVerdict.decision_trace[0] === 'object' ? finalVerdict.decision_trace[0].label : finalVerdict.decision_trace[0]}. ${typeof finalVerdict.decision_trace[1] === 'object' ? finalVerdict.decision_trace[1].label : finalVerdict.decision_trace[1]}. Immediate investigation of ${parsedAlert.asset ?? 'the affected asset'} is recommended.`
        }

        const narrator = narratorOutput ?? narratorFallback

        const triage = {
          severity:          finalVerdict.severity,
          classification:    finalVerdict.classification,
          confidence:        finalVerdict.confidence,
          asset_is_critical: finalVerdict.asset_is_critical,
          evidence:          finalVerdict.evidence,
          affected_asset:    (() => {
            // Priority 1: parser extracted a real asset name
            if (parsedAlert.asset && parsedAlert.asset !== 'UNKNOWN') return parsedAlert.asset
            if (parsedAlert.allAssets) {
              const first = parsedAlert.allAssets.split(',')[0]?.trim()
              if (first && first !== 'UNKNOWN') return first
            }
            // Priority 2: regex scan of raw alert text for computer/hostname patterns
            const computerPatterns = [
              /(?:Computer|ComputerName|Hostname|Workstation)[:\s=]+([A-Za-z0-9][A-Za-z0-9\-_.]{2,30})/i,
              /(?:host|device)[:\s=]+([A-Za-z0-9][A-Za-z0-9\-_.]{2,30})/i,
              /\\\\([A-Za-z0-9][A-Za-z0-9\-_.]{2,30})\\/i,
            ]
            for (const pat of computerPatterns) {
              const m = alertText.match(pat)
              if (m?.[1] && !['localhost','127','undefined','null'].includes(m[1].toLowerCase())) {
                return m[1].toUpperCase()
              }
            }
            // Priority 3: use username as host identifier
            if (parsedAlert.username && parsedAlert.username !== 'system' && !parsedAlert.username.includes('$')) {
              return `HOST:${parsedAlert.username.toUpperCase()}`
            }
            return 'UNKNOWN'
          })(),
          indicators: (() => {
            const raw = narrator?.indicators ?? narratorFallback.indicators ?? []
            const filtered = raw.filter(ind => {
              if (!ind || typeof ind !== 'string') return false
              const isTraceLabel = /^(CRITICAL|HIGH|MEDIUM|LOW)\s+across|^Critical:|^Confidence:|^Dominant:|^Supporting:/i.test(ind)
              return !isTraceLabel
            })
            return filtered.length > 0 ? filtered : (parsedAlert.allEventCodes ? [`EventCode=${parsedAlert.allEventCodes}`, `Asset=${parsedAlert.asset ?? 'UNKNOWN'}`, `User=${parsedAlert.username ?? 'UNKNOWN'}`] : raw)
          })(),
          mitre_id: (() => {
            if (finalVerdict.deterministicMitre) return finalVerdict.deterministicMitre
            if (narrator?.mitre_id && narrator.mitre_id !== 'T0000') return narrator.mitre_id
            return getClassificationMitre(finalVerdict.classification)?.id ?? 'T0000'
          })(),
          mitre_name: (() => {
            if (finalVerdict.deterministicMitre) return getMitreName(finalVerdict.deterministicMitre)
            if (narrator?.mitre_name) return narrator.mitre_name
            const fb = getClassificationMitre(finalVerdict.classification)
            return fb ? getMitreName(fb.id) ?? finalVerdict.classification : finalVerdict.classification
          })(),
          tactic: (() => {
            if (narrator?.tactic && narrator.tactic !== 'Unknown') return narrator.tactic
            return getClassificationMitre(finalVerdict.classification)?.tactic ?? 'Unknown'
          })(),
          mitre_tactic: (() => {
            if (narrator?.mitre_tactic && narrator.mitre_tactic !== 'Unknown') return narrator.mitre_tactic
            return getClassificationMitre(finalVerdict.classification)?.tactic ?? 'Unknown'
          })(),
          recommendations:           Array.isArray(narrator?.recommendations) ? narrator.recommendations : narratorFallback.recommendations,
          recommendation_provenance: narrator?.recommendation_provenance ?? [],
          reasoning: (() => {
            const r = narrator?.reasoning
            if (!r) return narratorFallback.reasoning
            if (Array.isArray(r)) return r.join(' ')
            if (typeof r === 'object' && r.text) return String(r.text)
            return String(r)
          })(),
        }

        if (triage.tactic !== triage.mitre_tactic) triage.mitre_tactic = triage.tactic

        while (triage.recommendations.length < 5) {
          triage.recommendations.push('Review alert context and escalate if indicators persist.')
        }

        const genericPatterns = [
          /^contact\s+(it|security|support|the team)/i,
          /^follow\s+(security|company|organizational)\s+polic/i,
          /^monitor\s+the\s+situation/i,
          /^be\s+aware/i,
          /^ensure\s+compliance/i,
          /^review\s+security\s+policies/i,
          /^update\s+antivirus/i,
          /^train\s+users/i,
          /^consider\s+implementing/i,
          /^it\s+is\s+recommended\s+to\s+consult/i,
          /^notify\s+(your|the)\s+(manager|supervisor|team)/i,
          /^document\s+the\s+incident\s+and\s+report/i,
          /^investigate\s+\w+\s+for\s+suspicious/i,
          /^review\s+logs\s+for/i,
          /^check\s+network\s+connections\s+from/i,
          /^escalate\s+to\s+senior/i,
          /^document\s+findings/i,
        ]

        const standardForensicSteps = [
          `Run: Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ComputerName ${triage.affected_asset ?? 'AFFECTED_HOST'} | Select -First 50`,
          `Isolate ${triage.affected_asset ?? 'AFFECTED_HOST'} from network pending investigation`,
          `Collect memory image from ${triage.affected_asset ?? 'AFFECTED_HOST'} before any remediation`,
          `Run: net user ${parsedAlert.username ?? 'AFFECTED_USER'} /domain — check account status`,
          `Run: schtasks /query /fo LIST /v on ${triage.affected_asset ?? 'AFFECTED_HOST'} — audit persistence`,
        ]

        triage.recommendations = (triage.recommendations ?? []).map((rec, i) => {
          if (!rec || typeof rec !== 'string') return standardForensicSteps[i] ?? standardForensicSteps[0]
          const isGeneric = genericPatterns.some(p => p.test(rec.trim()))
          const isActionable = /^Run:|Isolate|Block|Collect|Disable|Delete|Remove|Terminate|Investigate\s+\w+\s+(on|at)|schtasks|net user|Get-WinEvent|sc stop|netstat/i.test(rec.trim())
          if (isGeneric && !isActionable) return standardForensicSteps[i] ?? standardForensicSteps[0]
          return rec
        })

        if (!triage.recommendations.length) {
          triage.recommendations = standardForensicSteps
        }

        const requiredTriageFields = ['severity','classification','confidence','asset_is_critical','evidence','indicators','tactic','mitre_id','mitre_name','mitre_tactic','recommendations','reasoning']
        const missingFields = requiredTriageFields.filter(f => !(f in triage) || triage[f] === null || triage[f] === undefined)
        if (missingFields.length > 0) {
          console.error('[ARBITER] Output contract violation — missing fields:', missingFields)
          missingFields.forEach(f => {
            if (f === 'recommendations') triage[f] = narratorFallback.recommendations
            else if (f === 'reasoning') triage[f] = narratorFallback.reasoning
            else if (f === 'indicators') triage[f] = narratorFallback.indicators
            else if (typeof triage[f] === 'undefined') triage[f] = narratorFallback[f] ?? null
          })
        }

        const signalRuleToClassification = {
          BRUTE_FORCE_EXTREME: ['Brute Force Attack'],
          BRUTE_FORCE_HIGH: ['Brute Force Attack'],
          BRUTE_FORCE_MEDIUM: ['Password Spraying', 'Brute Force Attack'],
          LOGON_FAILURE_LOW: ['Failed Logon'],
          LOLBIN_CERTUTIL_DOWNLOAD: ['Malicious File Download via LOLBin', 'LOLBin Staging to Suspicious Path'],
          LOLBIN_CERTUTIL_SUSPICIOUS_PATH: ['LOLBin Staging to Suspicious Path', 'Malicious File Download via LOLBin'],
          LOLBIN_MSHTA_REMOTE: ['Remote Script Execution via mshta'],
          OFFICE_MACRO_DROPPER: ['Macro-based Dropper Execution'],
          POWERSHELL_ENCODED: ['Encoded PowerShell Execution'],
          SCHEDULED_TASK_CRADLE: ['Malicious Scheduled Task Persistence'],
          SCHEDULED_TASK_CREATED: ['Scheduled Task Created'],
          SERVICE_SUSPICIOUS_PATH: ['Suspicious Service Installation'],
          AUDIT_LOG_CLEARED: ['Security Log Tampering'],
          NTDS_ACCESS: ['Active Directory Credential Dump'],
          SAM_ACCESS: ['SAM Database Access'],
          ACTIVE_CAMPAIGN: ['Multi-Asset Coordinated Attack'],
          REPEATED_INDICATOR: ['Repeated Malicious Indicator'],
        }
        const dominantSignalRule = finalVerdict.signals?.[0]?.rule
        if (dominantSignalRule && signalRuleToClassification[dominantSignalRule]) {
          const allowedClassifications = signalRuleToClassification[dominantSignalRule]
          if (!allowedClassifications.includes(triage.classification)) {
            triage.classification = allowedClassifications[0]
          }
        }

        const caseId = `ARB-${startTime}`
        const allAffectedAssets = [
          triage.affected_asset,
          ...(parsedAlert.allAssets ?? '').split(',').map(s => s.trim()).filter(Boolean)
        ].filter(Boolean)
        await writeRedisContext(ips, normalizedUsername, { ...triage, allAffectedAssets }, caseId, safeSessionId)

        // Stream final triage result
        send(controller, 'triage', {
          triage,
          enrichment,
          ips,
          correlation: isCorrelated ? { hits: redisHits, summary: redisContext } : null,
          meta: {
            processingTime:           Date.now() - startTime,
            enrichmentSources:        enrichmentHealth.healthy,
            failedSources:            enrichmentHealth.failed,
            alertType:                parsedAlert.alertType,
            parseQuality:             parsedAlert.parseQuality,
            parsedFields:             Object.keys(parsedAlert).filter(k => parsedAlert[k] !== null),
            correlated:               isCorrelated,
            activeCampaign:           isActiveCampaign,
            uniqueAssets:             uniqueAssetCount,
            deterministicOverrides:   finalVerdict.decision_trace,
            decisionTrace:            finalVerdict.decision_trace,
            deterministicMitre:       finalVerdict.deterministicMitre,
            signals:                  (finalVerdict.signals ?? []).map(s => ({ rule: s.rule, label: s.label, severity: s.severity, category: s.category, ...(s.mitre ? { mitre: s.mitre } : {}) })),
            correlationPatterns:      redisPatterns,
            acs:                      acsObject,
          }
        })

        send(controller, 'done', {})

      } catch (err) {
        console.error('[ARBITER] Streaming error:', err)
        const is429 = err?.status === 429 || JSON.stringify(err).includes('rate_limit_exceeded')
        send(controller, 'error', {
          message: is429
            ? 'RATE_LIMIT'
            : err.message ?? 'Triage failed. Verify API keys and alert format.'
        })
      } finally {
        controller.close()
      }
    }
  })

  return new Response(stream, {
    headers: {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
    }
  })
}