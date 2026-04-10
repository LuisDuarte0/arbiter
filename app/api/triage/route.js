export const maxDuration = 60

import Groq from 'groq-sdk'
import { Redis } from '@upstash/redis'

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY })

const redis = new Redis({
  url:   process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
})

// ── SHARED INFRASTRUCTURE ─────────────────────────────────────────────────────
// Known shared infrastructure — CDN, cloud NAT, DNS resolvers
// IPs/CIDRs from these sources generate legitimate traffic and should not trigger campaign signals
const SHARED_INFRASTRUCTURE_CIDRS = [
  // Cloudflare
  '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '104.16.0.0/13', '104.24.0.0/14', '108.162.192.0/18',
  '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15',
  '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20',
  '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17',
  // Akamai
  '23.32.0.0/11', '23.64.0.0/14', '104.64.0.0/10',
  // Google DNS
  '8.8.8.0/24', '8.8.4.0/24',
  // Cloudflare DNS
  '1.1.1.0/24', '1.0.0.0/24',
]

function normalizeUsernameForCorrelation(username) {
  if (!username) return null
  let normalized = username.toLowerCase().trim()
  // Strip domain prefix: CORP\jsmith → jsmith, jsmith@corp.com → jsmith
  normalized = normalized.replace(/^[^\\]+\\/, '').replace(/@.+$/, '')
  // Strip common service account prefixes/suffixes
  normalized = normalized.replace(/^(svc[_-]|service[_-]|sa[_-])/, '').replace(/([_-]svc|[_-]service|[_-]sa|[_-]admin|[_-]adm)$/, '')
  // Remove non-alphanumeric except dot and hyphen
  normalized = normalized.replace(/[^a-z0-9.\-]/g, '')
  return normalized.length >= 3 ? normalized : null
}

function isSharedInfrastructure(ip) {
  if (!ip) return false
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(isNaN)) return false

  for (const cidr of SHARED_INFRASTRUCTURE_CIDRS) {
    const [network, prefix] = cidr.split('/')
    const prefixLen = parseInt(prefix, 10)
    const networkParts = network.split('.').map(Number)

    const ipInt = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    const netInt = (networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3]
    const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0

    if ((ipInt >>> 0 & mask) === (netInt >>> 0 & mask)) return true
  }
  return false
}

// ── REDIS TEMPORAL CORRELATION ────────────────────────────────────────────────
const REDIS_TTL = 86400 // 24 hours

async function getRedisContext(ips, username, sessionId) {
  const prefix = `session:${sessionId}:`
  const keys = []
  if (ips.length) ips.forEach(ip => {
    if (!isSharedInfrastructure(ip)) keys.push(`${prefix}ip:${ip}`)
  })
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
    if (isSharedInfrastructure(ip)) return // Skip Redis writes for shared infrastructure IPs
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
    /(?:User Name|TargetUserName|SubjectUserName|Username|User)[=:\s]+([A-Za-z0-9._@\\-]+)/i
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

  const isCloudTrail = (() => {
    try {
      const obj = JSON.parse(text)
      return !!(obj.eventName && (obj.eventTime || obj.eventSource || obj.awsRegion))
    } catch { return false }
  })()

  const isLinux = /sshd\[|auth\.log|sudo:|PAM|kernel\[|Failed password|Accepted (password|publickey)|CRON\[|crond\[|systemd\[|auditd\[|su\[|login\[/i.test(text)

  const cloudTrailEventName = isCloudTrail ? (() => { try { return JSON.parse(text).eventName } catch { return null } })() : null
  const cloudTrailUser      = isCloudTrail ? (() => { try { const o = JSON.parse(text); return o.userIdentity?.userName ?? null } catch { return null } })() : null
  const cloudTrailSrcIp     = isCloudTrail ? (() => { try { return JSON.parse(text).sourceIPAddress ?? null } catch { return null } })() : null

  return {
    eventId:       rawEventId,
    logonType:     get(['LogonType','logon_type'], /LogonType[=:\s]+(\d+)/i),
    failureReason: get(['FailureReason','Status'], /(?:FailureReason|Status)[=:\s]+(%%\d+|0x[0-9a-fA-F]+)/i),
    username:        rawUsername ? normalizeUsername(rawUsername) : (cloudTrailUser ?? null),
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
    srcIp:         get(['IpAddress','SourceNetworkAddress','SourceAddress'], /(?:IpAddress|SourceNetworkAddress|SourceAddress|srcIp|ipAddress)[=:\s]+(\S+)/i) ?? cloudTrailSrcIp,
    ipAddress:     get(['IpAddress'], /IpAddress[=:\s]+(\S+)/i),
    timestamp:     get(['TimeCreated'], /TimeCreated[=:\s]+(\S+)/i),
    cloudTrailEventName,
    cloudTrailUser,
    cloudTrailSrcIp,
    alertType:    isCloudTrail ? 'AWS CloudTrail' : isLinux ? 'Linux Security Event' : rawEventId ? 'Windows Security Event' : 'Generic Log',
    parseQuality: isCloudTrail ? 'structured' : isLinux ? 'structured' : rawEventId ? 'structured' : 'partial',
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

  const knownBenignIPs = new Set([
    '8.8.8.8', '8.8.4.4',                   // Google DNS
    '1.1.1.1', '1.0.0.1',                   // Cloudflare DNS
    '9.9.9.9',                               // Quad9 DNS
    '208.67.222.222', '208.67.220.220',      // OpenDNS
    '4.2.2.1', '4.2.2.2',                   // Level3 DNS
    '127.0.0.1', '0.0.0.0',                 // Localhost
    '255.255.255.255',                       // Broadcast
  ])

  // Strip recommendations that mention known benign IPs
  if (Array.isArray(triage.recommendations)) {
    triage.recommendations = triage.recommendations.map((rec, i) => {
      const ipMatches = rec.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []
      const hasBenignIP = ipMatches.some(ip => knownBenignIPs.has(ip))
      if (hasBenignIP) {
        const asset = triage.affected_asset ?? 'AFFECTED_HOST'
        return [
          `Isolate ${asset} from the network pending investigation`,
          `Verify all outbound connections from ${asset} for anomalies`,
          `Collect raw log files from ${asset} before remediation`,
          `Escalate indicators to threat intelligence platform for review`,
          `Preserve network captures from ${asset} for forensic analysis`,
        ][i] ?? `Investigate ${asset} and escalate if indicators persist`
      }
      return rec
    })
  }

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

function getSignals(parsed, enrichmentJudgment, redisHits, acsObject = null) {
  const signals = []

  const asset = (acsObject?.acs_data?.host ?? parsed.asset ?? '').toUpperCase()
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
      signals.push({ rule: 'ASSET_CRITICAL', classification: 'Critical Asset Targeted', label: cp.label, severity: cp.severity, confidence: cp.confidence, weight: cp.weight, evidence: [`asset=${acsObject?.acs_data?.host ?? parsed.asset ?? parsed.allAssets}`], category: 'asset', source: 'windows-eventid', signal_layer: 'enrichment', explanation_weight: cp.severity === 'CRITICAL' ? 'high' : 'medium', confidence_boost: cp.severity === 'CRITICAL' ? 15 : 10 })
      break
    }
  }

  const count = parseInt(acsObject?.acs_data?.count ?? parsed.count ?? '0', 10)
  const eventIds = (parsed.allEventCodes ?? parsed.eventId ?? '').split(',').map(s => s.trim())

  if (eventIds.includes('4625') || eventIds.includes('4771')) {
    if (count > 100) signals.push({ rule: 'BRUTE_FORCE_EXTREME', classification: 'Brute Force Attack', label: 'Extreme brute force volume', severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`EventCode=4625`, `Count=${count}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1110.001', explanation_weight: 'high', confidence_boost: 15 })
    else if (count > 20) signals.push({ rule: 'BRUTE_FORCE_HIGH', classification: 'Brute Force Attack', label: 'High-volume brute force', severity: 'CRITICAL', confidence: 90, weight: 4, evidence: [`EventCode=4625`, `Count=${count}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1110.001', explanation_weight: 'high', confidence_boost: 15 })
    else if (count > 5) signals.push({ rule: 'BRUTE_FORCE_MEDIUM', classification: 'Password Spraying', label: 'Repeated failed logons', severity: 'HIGH', confidence: 75, weight: 3, evidence: [`EventCode=4625`, `Count=${count}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1110.001', explanation_weight: 'medium', confidence_boost: 10 })
    else signals.push({ rule: 'LOGON_FAILURE_LOW', classification: 'Failed Logon', label: 'Low-count logon failure', severity: 'LOW', confidence: 70, weight: 1, evidence: [`EventCode=4625`, `Count=${count || '1'}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1110', explanation_weight: 'low', confidence_boost: 5 })
  }

  const cmdLine = (acsObject?.acs_data?.command_line ?? parsed.commandLine ?? '').toLowerCase()
  const procName = (acsObject?.acs_data?.process_name ?? parsed.processName ?? '').toLowerCase()
  const parentProc = (acsObject?.acs_data?.parent_process ?? parsed.parentProcess ?? '').toLowerCase()

  if (procName.includes('certutil') && /-urlcache|-split|-f/.test(cmdLine)) {
    signals.push({ rule: 'LOLBIN_CERTUTIL_DOWNLOAD', classification: 'Malicious File Download via LOLBin', label: 'certutil used as download cradle', severity: 'HIGH', confidence: 92, weight: 5, evidence: [`ProcessName=${acsObject?.acs_data?.process_name ?? parsed.processName}`, `CommandLine=${(acsObject?.acs_data?.command_line ?? parsed.commandLine)?.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1105', explanation_weight: 'medium', confidence_boost: 10 })
    if (/users\\public|windows\\temp|programdata/i.test(cmdLine))
      signals.push({ rule: 'LOLBIN_CERTUTIL_SUSPICIOUS_PATH', classification: 'LOLBin Staging to Suspicious Path', label: 'certutil writing to suspicious path', severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`CommandLine=${(acsObject?.acs_data?.command_line ?? parsed.commandLine)?.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1105', explanation_weight: 'high', confidence_boost: 15 })
  }

  if (procName.includes('mshta') && /http[s]?:\/\//i.test(cmdLine))
    signals.push({ rule: 'LOLBIN_MSHTA_REMOTE', classification: 'Remote Script Execution via mshta', label: 'mshta executing remote content', severity: 'HIGH', confidence: 90, weight: 5, evidence: [`ProcessName=${acsObject?.acs_data?.process_name ?? parsed.processName}`, `CommandLine=${(acsObject?.acs_data?.command_line ?? parsed.commandLine)?.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1218.005', explanation_weight: 'medium', confidence_boost: 10 })

  const officeParents = ['winword.exe','excel.exe','powerpnt.exe','outlook.exe']
  const lolbins = ['mshta.exe','wscript.exe','cscript.exe','powershell.exe','cmd.exe','certutil.exe','regsvr32.exe','rundll32.exe']
  if (officeParents.some(p => parentProc.includes(p)) && lolbins.some(l => procName.includes(l)))
    signals.push({ rule: 'OFFICE_MACRO_DROPPER', classification: 'Macro-based Dropper Execution', label: 'Office application spawning LOLBin', severity: 'CRITICAL', confidence: 98, weight: 5, evidence: [`ParentProcess=${acsObject?.acs_data?.parent_process ?? parsed.parentProcess}`, `ProcessName=${acsObject?.acs_data?.process_name ?? parsed.processName}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1204.002', explanation_weight: 'high', confidence_boost: 15 })

  if (procName.includes('powershell') && /-enc\b|-encodedcommand/i.test(cmdLine))
    signals.push({ rule: 'POWERSHELL_ENCODED', classification: 'Encoded PowerShell Execution', label: 'Encoded PowerShell command', severity: 'HIGH', confidence: 85, weight: 4, evidence: [`ProcessName=${acsObject?.acs_data?.process_name ?? parsed.processName}`, `CommandLine=${(acsObject?.acs_data?.command_line ?? parsed.commandLine)?.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1059.001', explanation_weight: 'medium', confidence_boost: 10 })

  if (eventIds.includes('4698') || eventIds.includes('4702')) {
    const taskContent = (acsObject?.acs_data?.task_content ?? parsed.taskContent ?? acsObject?.acs_data?.command_line ?? parsed.commandLine ?? parsed.taskName ?? '').toLowerCase()
    if (/iex|invoke-expression|downloadstring|-enc|certutil/i.test(taskContent))
      signals.push({ rule: 'SCHEDULED_TASK_CRADLE', classification: 'Malicious Scheduled Task Persistence', label: 'Scheduled task with download cradle', severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`EventCode=4698`, `TaskName=${parsed.taskName}`, `Content=${taskContent.slice(0,60)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1053.005', explanation_weight: 'high', confidence_boost: 15 })
    else
      signals.push({ rule: 'SCHEDULED_TASK_CREATED', classification: 'Scheduled Task Created', label: 'Scheduled task created', severity: 'MEDIUM', confidence: 60, weight: 2, evidence: [`EventCode=4698`, `TaskName=${parsed.taskName}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1053.005', explanation_weight: 'low', confidence_boost: 5 })
  }

  if (eventIds.includes('4697') || eventIds.includes('7045')) {
    const svcPath = (acsObject?.acs_data?.command_line ?? parsed.commandLine ?? acsObject?.acs_data?.object_name ?? parsed.objectName ?? '').toLowerCase()
    if (/users\\public|windows\\temp|programdata|appdata/i.test(svcPath))
      signals.push({ rule: 'SERVICE_SUSPICIOUS_PATH', classification: 'Suspicious Service Installation', label: 'Service binary in suspicious path', severity: 'CRITICAL', confidence: 93, weight: 5, evidence: [`EventCode=4697`, `ServiceName=${parsed.serviceName}`, `Path=${svcPath.slice(0,60)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1543.003', explanation_weight: 'high', confidence_boost: 15 })
  }

  if (eventIds.includes('1102') || eventIds.includes('4719'))
    signals.push({ rule: 'AUDIT_LOG_CLEARED', classification: 'Security Log Tampering', label: 'Security audit log cleared', severity: 'CRITICAL', confidence: 98, weight: 5, evidence: [`EventCode=${eventIds.includes('1102') ? '1102' : '4719'}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1070.001', explanation_weight: 'high', confidence_boost: 15 })

  if (eventIds.includes('4720')) {
    const targetUser = (acsObject?.acs_data?.target_user ?? parsed.targetUsername ?? acsObject?.acs_data?.user ?? parsed.username ?? '').toLowerCase()
    const isSuspiciousName = /backdoor|hack|persist|0day|temp|svc_|_svc|admin_/i.test(targetUser)
    if (isSuspiciousName) {
      signals.push({ rule: 'ACCOUNT_CREATED_SUSPICIOUS', classification: 'Suspicious Account Creation', label: `Suspicious account created: ${acsObject?.acs_data?.target_user ?? parsed.targetUsername ?? acsObject?.acs_data?.user ?? parsed.username}`, severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`EventCode=4720`, `TargetUserName=${acsObject?.acs_data?.target_user ?? parsed.targetUsername ?? acsObject?.acs_data?.user ?? parsed.username}`, `CreatedBy=${acsObject?.acs_data?.user ?? parsed.username}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1136.001', explanation_weight: 'high', confidence_boost: 15 })
    } else {
      signals.push({ rule: 'ACCOUNT_CREATED', classification: 'New Account Creation', label: 'New user account created', severity: 'MEDIUM', confidence: 65, weight: 3, evidence: [`EventCode=4720`, `TargetUserName=${acsObject?.acs_data?.target_user ?? parsed.targetUsername ?? acsObject?.acs_data?.user ?? parsed.username}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1136.001', explanation_weight: 'low', confidence_boost: 5 })
    }
  }

  if (eventIds.includes('4663') || eventIds.includes('4656')) {
    const obj = (acsObject?.acs_data?.object_name ?? parsed.objectName ?? '').toLowerCase()
    if (obj.includes('ntds.dit')) signals.push({ rule: 'NTDS_ACCESS', classification: 'Active Directory Credential Dump', label: 'ntds.dit accessed', severity: 'CRITICAL', confidence: 99, weight: 5, evidence: [`EventCode=4663`, `ObjectName=${acsObject?.acs_data?.object_name ?? parsed.objectName}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1003.003', explanation_weight: 'high', confidence_boost: 15 })
    else if (obj.includes('sam')) signals.push({ rule: 'SAM_ACCESS', classification: 'SAM Database Access', label: 'SAM database accessed', severity: 'CRITICAL', confidence: 96, weight: 5, evidence: [`EventCode=4663`, `ObjectName=${acsObject?.acs_data?.object_name ?? parsed.objectName}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1003.002', explanation_weight: 'high', confidence_boost: 15 })
  }

  if (procName && cmdLine) {
    const isRundll32 = procName.includes('rundll32')
    const isLsassDump = /comsvcs|minidump|lsass/i.test(cmdLine)
    const isMimikatz = /mimikatz|sekurlsa|privilege::debug/i.test(cmdLine)
    if (isRundll32 && isLsassDump) {
      signals.push({ rule: 'LSASS_DUMP_RUNDLL32', classification: 'LSASS Memory Dump via LOLBin', label: 'LSASS memory dump via rundll32/comsvcs', severity: 'CRITICAL', confidence: 99, weight: 5, evidence: [`ProcessName=${acsObject?.acs_data?.process_name ?? parsed.processName}`, `CommandLine=${(acsObject?.acs_data?.command_line ?? parsed.commandLine)?.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1003.001', explanation_weight: 'high', confidence_boost: 15 })
    }
    if (isMimikatz) {
      signals.push({ rule: 'MIMIKATZ_DETECTED', classification: 'Mimikatz Credential Dumping', label: 'Mimikatz credential dumping detected', severity: 'CRITICAL', confidence: 99, weight: 5, evidence: [`CommandLine=${(acsObject?.acs_data?.command_line ?? parsed.commandLine)?.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1003.001', explanation_weight: 'high', confidence_boost: 15 })
    }
  }

  const verdict = enrichmentJudgment?.judgment
  if (verdict === 'CONFIRMED_MALICIOUS') signals.push({ rule: 'ENRICHMENT_CONFIRMED_MALICIOUS', classification: 'Connection from Known Malicious IP', label: 'IP confirmed malicious', severity: 'HIGH', confidence: 80, weight: 3, evidence: [`enrichmentVerdict=CONFIRMED_MALICIOUS`], category: 'enrichment', source: 'windows-eventid', signal_layer: 'enrichment', mitre: null, explanation_weight: 'medium', confidence_boost: 10 })
  else if (verdict === 'SUSPICIOUS') signals.push({ rule: 'ENRICHMENT_SUSPICIOUS', classification: 'Connection from Suspicious IP', label: 'IP flagged suspicious', severity: 'MEDIUM', confidence: 60, weight: 2, evidence: [`enrichmentVerdict=SUSPICIOUS`], category: 'enrichment', source: 'windows-eventid', signal_layer: 'enrichment', mitre: null, explanation_weight: 'low', confidence_boost: 5 })
  else if (verdict === 'CLEAN') signals.push({ rule: 'ENRICHMENT_CLEAN', classification: 'Network Connection — Clean Source', label: 'IP clean across all sources', severity: 'LOW', confidence: 50, weight: 1, evidence: [`enrichmentVerdict=CLEAN`], category: 'enrichment', source: 'windows-eventid', signal_layer: 'enrichment', mitre: null, explanation_weight: 'low', confidence_boost: 5 })

  if (redisHits?.length > 0) {
    const maxCount = redisHits.reduce((max, h) => Math.max(max, h.count ?? 0), 0)
    const uniqueAssets = new Set(redisHits.flatMap(h => h.assets ?? [])).size
    if (maxCount >= 2 && uniqueAssets >= 2) signals.push({ rule: 'ACTIVE_CAMPAIGN', classification: 'Multi-Asset Coordinated Attack', label: `Active campaign — ${maxCount} hits across ${uniqueAssets} assets`, severity: 'CRITICAL', confidence: 90, weight: 5, evidence: [`redisHits=${maxCount}`, `uniqueAssets=${uniqueAssets}`], category: 'frequency', source: 'redis', signal_layer: 'behavioral', mitre: 'T1078', explanation_weight: 'high', confidence_boost: 15 })
    else if (maxCount >= 2) signals.push({ rule: 'REPEATED_INDICATOR', classification: 'Repeated Malicious Indicator', label: `Indicator seen ${maxCount}× in last 24h`, severity: 'HIGH', confidence: 75, weight: 3, evidence: [`redisHits=${maxCount}`], category: 'frequency', source: 'redis', signal_layer: 'behavioral', mitre: 'T1078', explanation_weight: 'medium', confidence_boost: 10 })
  }

  // ── ACS BEHAVIORAL SIGNALS ────────────────────────────────────────────────
  // These signals fire from acs_data only — vendor-agnostic, format-blind.
  // They run alongside existing EventID signals, not replacing them.
  // Priority: existing behavioral signals (weight 5) > ACS signals (weight 3-4)
  // to avoid double-counting.

  const acs = acsObject?.acs_data
  const acsVendor = acsObject?.meta?.vendor_origin ?? 'unknown'
  const normScore = acsObject?.meta?.normalization_score ?? 0

  if (acs && normScore >= 0.5) {

    // AUTH FAILURE — vendor agnostic brute force detection
    if (acs.event_type === 'auth' && acs.event_outcome === 'failure') {
      const count = acs.count ?? 1
      if (count > 20) {
        signals.push({ rule: 'ACS_AUTH_FAILURE_MASS', classification: 'Mass Authentication Attack', label: `Mass authentication failures (${count}×) via ${acsVendor}`, severity: 'CRITICAL', confidence: 88, weight: 4, evidence: [`event_type=auth`, `event_outcome=failure`, `count=${count}`, `src_ip=${acs.src_ip ?? 'unknown'}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1110' })
      } else if (count > 5) {
        signals.push({ rule: 'ACS_AUTH_FAILURE_HIGH', classification: 'Repeated Authentication Failures', label: `Repeated authentication failures (${count}×) via ${acsVendor}`, severity: 'HIGH', confidence: 75, weight: 3, evidence: [`event_type=auth`, `event_outcome=failure`, `count=${count}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1110' })
      } else {
        signals.push({ rule: 'ACS_AUTH_FAILURE_LOW', classification: 'Authentication Failure', label: `Authentication failure via ${acsVendor}`, severity: 'LOW', confidence: 55, weight: 2, evidence: [`event_type=auth`, `event_outcome=failure`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1110' })
      }
    }

    // ACCOUNT DELETION — IAM/directory account removal (evidence destruction indicator)
    if (acs.event_type === 'privilege' && /deleteuser|deleterole|deletegroup/i.test(acs.action ?? '')) {
      signals.push({ rule: 'ACS_ACCOUNT_DELETION', classification: 'Account Deletion — Potential Evidence Destruction', label: `Account deletion detected: ${acs.action} via ${acsVendor}`, severity: 'HIGH', confidence: 82, weight: 4, evidence: [`event_type=privilege`, `action=${acs.action}`, `user=${acs.user ?? 'unknown'}`, `target=${acsObject?.acs_data?.target_user ?? 'unknown'}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1070.001' })
    }

    // PRIVILEGE ESCALATION — sudo, role assumption, policy changes
    if (acs.event_type === 'privilege' && acs.action !== 'unknown') {
      signals.push({ rule: 'ACS_PRIVILEGE_ACTION', classification: 'Privilege Escalation Detected', label: `Privilege action detected: ${acs.action} via ${acsVendor}`, severity: 'MEDIUM', confidence: 65, weight: 3, evidence: [`event_type=privilege`, `action=${acs.action}`, `user=${acs.user ?? 'unknown'}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1078' })
    }

    // CREDENTIAL-SENSITIVE OBJECT ACCESS — fires without process creation context
    // Covers LSASS file access, SAM access, cloud IMDS credential theft, shadow/passwd
    if (acs.resource) {
      const resource = acs.resource.toLowerCase()
      const isSensitiveResource = /ntds\.dit|lsass|\/sam$|security-credentials|\.aws\/credentials|\/shadow$|\/passwd$|\/etc\/shadow|\/proc\/\d+\/mem|krbtgt|ntlm|secretsdump/i.test(resource)
      if (isSensitiveResource && !signals.some(s => s.rule === 'LSASS_DUMP_RUNDLL32' || s.rule === 'NTDS_ACCESS' || s.rule === 'SAM_ACCESS')) {
        signals.push({
          rule: 'ACS_OBJECT_ACCESS_SENSITIVE',
          classification: 'Credential Resource Access',
          label: `Sensitive credential resource accessed: ${acs.resource}`,
          severity: 'HIGH',
          confidence: 78,
          weight: 4,
          evidence: [`event_type=${acs.event_type}`, `resource=${acs.resource}`, `user=${acs.user ?? 'unknown'}`],
          category: 'behavioral',
          source: 'acs',
          signal_layer: 'behavioral',
          mitre: 'T1003'
        })
      }
    }

    // LATERAL MOVEMENT CANDIDATE — successful network logon from internal source to different host
    // Flags but does not accuse — enrichment/campaign layer escalates if warranted
    if (
      acs.event_type === 'auth' &&
      acs.event_outcome === 'success' &&
      (acs.action === 'logon' || acs.action === 'logon_explicit') &&
      acs.src_ip &&
      acs.host
    ) {
      const isInternalSrc = /^10\.|^172\.(1[6-9]|2\d|3[01])\.|^192\.168\./i.test(acs.src_ip)
      const srcDiffFromDest = acs.src_ip !== acs.host
      if (isInternalSrc && srcDiffFromDest) {
        signals.push({
          rule: 'ACS_LATERAL_MOVEMENT_CANDIDATE',
          classification: 'Lateral Movement Candidate',
          label: `Internal network logon: ${acs.src_ip} → ${acs.host}`,
          severity: 'MEDIUM',
          confidence: 50,
          weight: 2,
          evidence: [`event_type=auth`, `event_outcome=success`, `src_ip=${acs.src_ip}`, `host=${acs.host}`],
          category: 'behavioral',
          source: 'acs',
          signal_layer: 'behavioral',
          mitre: 'T1021'
        })
      }
    }

    // SUSPICIOUS DATA ACCESS — cloud storage read on sensitive resources
    if (acs.event_type === 'network' && /getobject|read|download|headobject|listobjects/i.test(acs.action ?? '')) {
      const resource = (acs.resource ?? '').toLowerCase()
      const user = (acs.user ?? '').toLowerCase()
      const sensitiveResource = /prod|financial|finance|secure|backup|secret|confidential|private|pii|credential|password|key/i.test(resource)
      const suspiciousUser = /contractor|temp|tmp|test|intern|vendor|external/i.test(user)

      if (sensitiveResource || suspiciousUser) {
        // Recurrence suppression — if same user seen 3+ times in session
        // without other malicious indicators, downgrade to LOW to prevent alert fatigue
        const hasOtherMalicious = signals.some(s => s.rule === 'ENRICHMENT_CONFIRMED_MALICIOUS' || s.rule === 'ENRICHMENT_SUSPICIOUS')
        // Use combined IP+user Redis count for recurrence — same method as ACS_HIGH_VOLUME_DATA_ACCESS
        const sessionHitCount = redisHits?.filter(h =>
          h.key?.includes(`ip:${acs.src_ip}`) || h.key?.includes(`user:${acs.user}`)
        ).reduce((sum, h) => sum + (h.count ?? 0), 0) ?? 0
        // Also check if high-volume signal already fired — if so, recurrence is confirmed
        const highVolumeAlreadyFired = signals.some(s => s.rule === 'ACS_HIGH_VOLUME_DATA_ACCESS')
        const isRecurring = (sessionHitCount >= 3 || highVolumeAlreadyFired) && !hasOtherMalicious

        const severity = isRecurring ? 'LOW' : (sensitiveResource && suspiciousUser ? 'HIGH' : 'MEDIUM')
        const confidence = isRecurring ? 35 : (sensitiveResource && suspiciousUser ? 82 : 65)
        const label = isRecurring
          ? `Recurring data access pattern: ${acs.action} on ${acs.resource ?? 'unknown'} by ${acs.user ?? 'unknown'} (possible legitimate operation)`
          : `Suspicious data access: ${acs.action} on ${acs.resource ?? 'unknown resource'} by ${acs.user ?? 'unknown user'}`

        signals.push({
          rule: 'ACS_SUSPICIOUS_DATA_ACCESS',
          classification: sensitiveResource && suspiciousUser ? 'Suspicious Cloud Data Access' : sensitiveResource ? 'Sensitive Resource Access' : 'Suspicious User Data Access',
          label,
          severity,
          confidence,
          weight: 3,
          evidence: [`event_type=network`, `action=${acs.action}`, `resource=${acs.resource ?? 'unknown'}`, `user=${acs.user ?? 'unknown'}`],
          category: 'behavioral',
          source: 'acs',
          signal_layer: 'behavioral',
          mitre: 'T1530'
        })
      }
    }

    // CLOUD SPECIFIC — IAM and data exfil patterns
    if (acsVendor === 'cloudtrail') {
      if (acs.action?.includes('putuserpolicy') || acs.action?.includes('attachpolicy') || acs.action?.includes('attachuserpolicy') || acs.action?.includes('attachrolepolicy') || acs.action?.includes('putrolepolicy')) {
        signals.push({ rule: 'ACS_CLOUD_PRIVILEGE_ESCALATION', classification: 'Cloud IAM Privilege Escalation', label: 'Cloud IAM privilege escalation detected', severity: 'HIGH', confidence: 85, weight: 4, evidence: [`action=${acs.action}`, `user=${acs.user ?? 'unknown'}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1098' })
      }
      if (acs.event_outcome === 'failure' && acs.action?.includes('assume')) {
        signals.push({ rule: 'ACS_CLOUD_ROLE_ASSUMPTION_FAIL', classification: 'Cloud Role Assumption Failure', label: 'Failed cloud role assumption attempt', severity: 'MEDIUM', confidence: 70, weight: 3, evidence: [`action=${acs.action}`, `src_ip=${acs.src_ip ?? 'unknown'}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1078.004' })
      }

      // HIGH VOLUME DATA ACCESS — repeated access to same resource within session
      if (acs.event_type === 'network' && acs.resource && acs.user) {
        const redisHitCount = redisHits?.filter(h =>
          h.key?.includes(`ip:${acs.src_ip}`) || h.key?.includes(`user:${acs.user}`)
        ).reduce((sum, h) => sum + (h.count ?? 0), 0) ?? 0

        if (redisHitCount >= 3) {
          signals.push({
            rule: 'ACS_HIGH_VOLUME_DATA_ACCESS',
            classification: 'High-Volume Cloud Data Access',
            label: `High-frequency data access: ${acs.user} accessed ${acs.resource} ${redisHitCount}× in session`,
            severity: 'HIGH',
            confidence: 75,
            weight: 3,
            evidence: [`user=${acs.user}`, `resource=${acs.resource}`, `session_count=${redisHitCount}`],
            category: 'behavioral',
            source: 'acs',
            signal_layer: 'behavioral',
            mitre: 'T1530'
          })
        }
      }
    }

  }

  // COMMAND-LINE SIGNALS — lower normScore threshold: command_line extraction is independent of normalization
  if (acs && acs.command_line && normScore >= 0.2) {
    const cmd = acs.command_line.toLowerCase()

    if (/wget|curl.*http|bash.*-c.*http|python.*urllib|nc\s+-e|ncat|mshta.*http|certutil.*http|certutil.*-urlcache|bitsadmin.*http|regsvr32.*http|rundll32.*http|wscript.*http/i.test(cmd)) {
      signals.push({ rule: 'ACS_REMOTE_DOWNLOAD', classification: 'Remote File Download via Command Line', label: `Remote download/execution via command line (${acsVendor})`, severity: 'HIGH', confidence: 82, weight: 4, evidence: [`command_line=${acs.command_line.slice(0, 80)}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1105' })
    }

    if (/base64.*decode|echo.*\|.*base64|openssl.*base64|base64\s+-d/i.test(cmd)) {
      signals.push({ rule: 'ACS_BASE64_EXECUTION', classification: 'Obfuscated Command Execution', label: `Base64-encoded command execution (${acsVendor})`, severity: 'HIGH', confidence: 80, weight: 4, evidence: [`command_line=${acs.command_line.slice(0, 80)}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1027' })
    }

    const isSudoContext = acsVendor === 'linux' && (acs.action === 'privilege_escalation' || acs.action === 'command_executed')
    const shellBinary = /\/(bash|sh|python|perl|ruby|php|nc|ncat)\s*$|sudo\s+(bash|sh|python|perl|ruby|php|nc|ncat)/i.test(cmd)
    if (isSudoContext && shellBinary) {
      signals.push({ rule: 'ACS_SUDO_SHELL', classification: 'Privilege Abuse via Sudo Shell', label: `Sudo to interactive shell (${acsVendor})`, severity: 'CRITICAL', confidence: 90, weight: 4, evidence: [`command_line=${acs.command_line.slice(0, 80)}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1548.003' })
    }
  }

  // PARTIAL DETECTION — outside normScore guard, fires on generic low-confidence normalization
  // Suppressed when a strong behavioral signal (weight >= 3) already exists — avoid noise
  const hasStrongBehavioralSignal = signals.some(s => s.signal_layer === 'behavioral' && (s.weight ?? 0) >= 3)
  if (acsObject?.meta?.is_generic && normScore < 0.5 && !hasStrongBehavioralSignal) {
    signals.push({ rule: 'ACS_PARTIAL_DETECTION', classification: 'Partial Detection — Unknown Log Format', label: 'Partial normalization — limited behavioral detection', severity: 'LOW', confidence: 30, weight: 1, evidence: [`normalization_score=${normScore}`, `vendor=unknown`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: null })
  }

  return signals
}

function aggregateSignals(signals, parseQuality = 'structured') {
  if (!signals.length) return { severity: 'LOW', classification: 'UNKNOWN', confidence: 20, asset_is_critical: false, evidence: [], decision_trace: ['No rules matched — defaulting to LOW/UNKNOWN'] }

  const severityRank   = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }
  const severityByRank = { 4: 'CRITICAL', 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW' }

  // ── Layer separation ────────────────────────────────────────────────────────
  const isBehavioral  = s => s.signal_layer === 'behavioral' || (!s.signal_layer && (s.category === 'behavioral' || s.category === 'asset' || s.category === 'frequency'))
  const isEnrichment  = s => s.signal_layer === 'enrichment'  || (!s.signal_layer && s.category === 'enrichment')
  const behavioralSignals = signals.filter(isBehavioral)
  const enrichmentSignals = signals.filter(isEnrichment)

  const sortLayer = arr => [...arr].sort((a, b) => {
    const wDiff = b.weight - a.weight
    if (wDiff !== 0) return wDiff
    return b.confidence - a.confidence
  })
  const sortedBehavioral = sortLayer(behavioralSignals)
  const sortedEnrichment = sortLayer(enrichmentSignals)

  const hasBehavioral = sortedBehavioral.length > 0
  const dominant = sortedBehavioral[0] ?? sortedEnrichment[0] ?? signals[0]

  // ── Severity: behavioral base, enrichment boosts max 1 level ──────────────
  const baseSeverityRank = hasBehavioral
    ? Math.max(...sortedBehavioral.map(s => severityRank[s.severity] ?? 1))
    : (severityRank[dominant.severity] ?? 1)

  let finalSeverityRank = baseSeverityRank
  if (enrichmentSignals.length > 0) {
    const maxEnrichRank = Math.max(...enrichmentSignals.map(s => severityRank[s.severity] ?? 1))
    finalSeverityRank = Math.min(baseSeverityRank + 1, Math.max(baseSeverityRank, maxEnrichRank))
  }
  finalSeverityRank = Math.min(finalSeverityRank, 4)

  // Severity floor: confirmed malicious IP always elevates to minimum HIGH
  const hasConfirmedMalicious = signals.some(s => s.rule === 'ENRICHMENT_CONFIRMED_MALICIOUS')
  const flooredSeverityRank = hasConfirmedMalicious ? Math.max(finalSeverityRank, 3) : finalSeverityRank
  const finalSeverity = severityByRank[flooredSeverityRank] ?? 'LOW'
  const severityWasFloored = hasConfirmedMalicious && flooredSeverityRank > finalSeverityRank
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
    ACS_AUTH_FAILURE_LOW:              'Authentication Failure',
    ACS_AUTH_FAILURE_HIGH:             'Repeated Authentication Failures',
    ACS_AUTH_FAILURE_MASS:             'Mass Authentication Attack',
    ACS_PRIVILEGE_ACTION:              'Privilege Escalation Detected',
    ACS_REMOTE_DOWNLOAD:               'Remote File Download via Command Line',
    ACS_BASE64_EXECUTION:              'Obfuscated Command Execution',
    ACS_SUDO_SHELL:                    'Privilege Abuse via Sudo Shell',
    ACS_CLOUD_PRIVILEGE_ESCALATION:    'Cloud IAM Privilege Escalation',
    ACS_CLOUD_ROLE_ASSUMPTION_FAIL:    'Cloud Role Assumption Failure',
    ACS_SUSPICIOUS_DATA_ACCESS:        'Suspicious Cloud Data Access',
    ACS_OBJECT_ACCESS_SENSITIVE:       'Credential Resource Access',
    ACS_LATERAL_MOVEMENT_CANDIDATE:   'Lateral Movement Candidate',
    ACS_HIGH_VOLUME_DATA_ACCESS:       'High-Volume Cloud Data Access',
    ACS_ACCOUNT_DELETION:              'Account Deletion — Potential Evidence Destruction',
    ACS_PARTIAL_DETECTION:             'Partial Detection — Unknown Log Format',
  }

  // Classification priority: event-specific behavioral > campaign/frequency > enrichment
  // Campaign signals define severity but should not override event-specific classification
  const eventBehavioral = sortedBehavioral.find(s => s.category === 'behavioral')
  const campaignBehavioral = sortedBehavioral.find(s => s.category === 'frequency')
  const topEnrichment = sortedEnrichment.find(s => s.category !== 'asset' && s.category !== 'frequency')

  // If event-specific behavioral signal is weak (weight < 3) AND campaign/frequency signal
  // is strong (weight >= 4), campaign defines both severity AND classification
  // This prevents "Authentication Failure — CRITICAL" when campaign is the real story
  const genericAcsRules = ['ACS_PRIVILEGE_ACTION', 'ACS_AUTH_FAILURE_LOW', 'ACS_PARTIAL_DETECTION']
  const eventBehavioralIsWeak = eventBehavioral && (eventBehavioral.weight ?? 0) < 3
  const eventBehavioralIsGeneric = eventBehavioral && genericAcsRules.includes(eventBehavioral.rule)
  const campaignIsStrong = campaignBehavioral && (campaignBehavioral.weight ?? 0) >= 4

  // When event behavioral signal is a generic catch-all AND a specific enrichment signal
  // has its own classification, prefer the enrichment classification
  // This prevents "Privilege Escalation Detected" from overriding "Security Log Tampering"
  const specificEnrichment = sortedEnrichment.find(s =>
    s.classification &&
    s.category !== 'asset' &&
    s.rule !== 'ENRICHMENT_CONFIRMED_MALICIOUS' &&
    s.rule !== 'ENRICHMENT_SUSPICIOUS' &&
    s.rule !== 'ENRICHMENT_CLEAN'
  )

  const classificationSource = (eventBehavioralIsWeak && campaignIsStrong)
    ? campaignBehavioral
    : (eventBehavioralIsGeneric && specificEnrichment)
    ? specificEnrichment
    : eventBehavioral ?? campaignBehavioral ?? topEnrichment ?? dominant

  const classificationReason = (eventBehavioralIsWeak && campaignIsStrong)
    ? 'campaign_dominates'
    : (eventBehavioralIsGeneric && specificEnrichment)
    ? 'enrichment_specific'
    : eventBehavioral ? 'event_behavioral'
    : campaignBehavioral ? 'campaign_behavioral'
    : topEnrichment ? 'enrichment'
    : 'dominant'

  const classification = classificationSource?.classification ?? classificationMap[classificationSource?.rule] ?? 'UNKNOWN'
  // If classification source is a generic ACS catch-all, prefer the most specific enrichment MITRE
  const classificationIsGeneric = genericAcsRules.includes(classificationSource?.rule)
  const specificEnrichmentMitre = sortedEnrichment.find(s => s.mitre && s.rule !== 'ENRICHMENT_CONFIRMED_MALICIOUS' && s.rule !== 'ENRICHMENT_SUSPICIOUS' && s.rule !== 'ENRICHMENT_CLEAN')?.mitre

  const deterministicMitre = (!classificationIsGeneric ? classificationSource?.mitre : null)
    ?? specificEnrichmentMitre
    ?? sortedBehavioral.find(s => s.mitre)?.mitre
    ?? sortedEnrichment.find(s => s.mitre)?.mitre
    ?? null

  // ── Confidence: behavioral base + capped enrichment boost ─────────────────
  const top3 = (sortedBehavioral.length > 0 ? sortedBehavioral : sortedEnrichment).slice(0, 3)
  const baseConfidence = top3.reduce((sum, s) => sum + s.confidence * s.weight, 0) / Math.max(top3.reduce((sum, s) => sum + s.weight, 0), 1)
  const eventidBoost   = Math.min(enrichmentSignals.reduce((max, s) => Math.max(max, s.confidence_boost ?? 0), 0), 15)
  const campaignBonus  = signals.some(s => s.rule === 'ACTIVE_CAMPAIGN') ? 10 : 0
  const unknownPenalty = classification === 'UNKNOWN' ? -20 : 0
  const parseBonus     = parseQuality === 'structured' ? 10 : parseQuality === 'partial' ? 0 : -10
  const finalConfidence = Math.round(Math.max(0, Math.min(100, baseConfidence + parseBonus + campaignBonus + unknownPenalty + eventidBoost)))

  // ── Layer summary ──────────────────────────────────────────────────────────
  const layer_summary = {
    behavioral:      sortedBehavioral.length,
    enrichment:      enrichmentSignals.length,
    dominant_layer:  hasBehavioral ? 'behavioral' : 'enrichment',
    severity_boosted: finalSeverityRank > baseSeverityRank,
  }

  const decision_trace = [
    { type: 'dominant',      label: dominant.label, category: dominant.category, weight: dominant.weight, confidence: dominant.confidence, rule: dominant.rule },
    { type: 'severity',      label: `${finalSeverity} across ${signals.length} signals`, value: finalSeverity },
    ...(severityWasFloored ? [{ type: 'floor', label: `Severity elevated to HIGH minimum — confirmed malicious IP present`, rule: 'ENRICHMENT_CONFIRMED_MALICIOUS', from: severityByRank[finalSeverityRank], to: finalSeverity }] : []),
    { type: 'classification', label: classification, rule: classificationSource?.rule, layer: classificationSource?.signal_layer, reason: classificationReason },
    { type: 'asset',         label: `Critical: ${assetIsCritical}`, value: assetIsCritical },
    { type: 'confidence',    label: `${finalConfidence}`, base: Math.round(baseConfidence), campaignBonus, unknownPenalty, parseBonus, eventidBoost },
    { type: 'layer_summary', label: `behavioral=${layer_summary.behavioral} enrichment=${layer_summary.enrichment} dominant=${layer_summary.dominant_layer}${layer_summary.severity_boosted ? ' [severity boosted]' : ''}`, ...layer_summary },
    ...[...sortedBehavioral.slice(1), ...sortedEnrichment].map(s => ({ type: 'supporting', label: s.label, severity: s.severity, category: s.category, rule: s.rule, signal_layer: s.signal_layer }))
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

function buildNarratorPrompt(sanitizedAlert, parsedContext, enrichmentJudgment, redisContext, isActiveCampaign, uniqueAssetCount, frequencyMultiplier, finalVerdict, acsObject = null) {
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
VENDOR ORIGIN: ${acsObject?.meta?.vendor_origin ?? 'unknown'}
NORMALIZATION SCORE: ${acsObject?.meta?.normalization_score ?? 0}
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

PLATFORM CONSTRAINT (ABSOLUTE — NO EXCEPTIONS):
${(() => {
  const v = acsObject?.meta?.vendor_origin
  if (v === 'linux') return `This is a LINUX system. You MUST use ONLY Linux commands in recommendations:
  - journalctl -u sshd, grep, awk, sed, tail
  - systemctl stop/status, ss -tulpn, who, last, w
  - ausearch -m USER_LOGIN, aureport
  - /var/log/auth.log, /var/log/syslog
  FORBIDDEN: Get-WinEvent, schtasks, net user, PowerShell, wmic, reg query, sc stop`
  if (v === 'cloudtrail') return `This is AWS CloudTrail. You MUST use ONLY AWS CLI commands in recommendations:
  - aws cloudtrail lookup-events
  - aws iam get-user, aws iam list-attached-user-policies
  - aws iam delete-user-policy, aws iam detach-user-policy
  - aws s3 ls, aws s3api get-bucket-policy
  - aws ec2 describe-instances, aws ec2 stop-instances
  FORBIDDEN: Get-WinEvent, schtasks, net user, PowerShell, journalctl, systemctl`
  if (v === 'windows') return `This is a WINDOWS system. You MUST use ONLY Windows commands in recommendations:
  - Get-WinEvent, PowerShell, wmic, reg query
  - net user, net localgroup, sc stop, schtasks
  - Invoke-Command, Get-Process, Get-Service
  FORBIDDEN: journalctl, systemctl, aws cli, kubectl`
  const behavioralSignals = (finalVerdict.signals ?? [])
    .filter(s => s.signal_layer === 'behavioral' && s.weight >= 3 && s.rule !== 'ACS_PARTIAL_DETECTION' && s.rule !== 'ACTIVE_CAMPAIGN')
    .slice(0, 3)

  const signalContext = behavioralSignals.length > 0
    ? `CONFIRMED ATTACK BEHAVIORS — EACH RECOMMENDATION MUST ADDRESS ONE OF THESE:
${behavioralSignals.map(s => `- [${s.rule}] ${s.label} → MITRE ${s.mitre ?? 'unknown'}`).join('\n')}

REQUIRED recommendation structure when behaviors detected:
01: CONTAIN the specific behavior listed above (block the command, terminate the process, isolate the source)
02: INVESTIGATE the specific technique (search logs for the exact pattern that triggered the signal)
03: VALIDATE scope (determine what else this technique may have affected)
04: HARDEN against recurrence (remove persistence, block execution path)
05: PRESERVE evidence specific to the detected technique\n`
    : ''

  return `UNKNOWN/GENERIC LOG SOURCE.
${signalContext}ALL 5 recommendations MUST be platform-agnostic investigation steps:
- Network-level: block or monitor the source IP at the firewall
- Identity: verify and disable any mentioned user accounts through your IAM system
- Evidence: preserve raw log files before any remediation
- Escalation: forward indicators to threat intelligence platform
- Containment: isolate the affected host at the network level if a hostname was identified
STRICTLY FORBIDDEN: Get-WinEvent, schtasks, net user, PowerShell, journalctl, systemctl, aws, kubectl, any platform-specific command
Use generic verbs: Isolate, Block, Verify, Preserve, Escalate, Investigate
When CONFIRMED ATTACK BEHAVIORS are listed above, ALL 5 recommendations MUST follow the required structure above and directly address those specific behaviors.`
})()}

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
    'T1027':     'Obfuscated Files or Information',
    'T1548.003': 'Abuse Elevation Control Mechanism: Sudo',
    'T1098':     'Account Manipulation',
    'T1078.004': 'Valid Accounts: Cloud Accounts',
    'T1530':     'Data from Cloud Storage',
    'T1003':     'OS Credential Dumping',
    'T1021':     'Remote Services',
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
    'Account Deletion — Potential Evidence Destruction': { id: 'T1070.001', tactic: 'Defense Evasion' },
    'Active Directory Credential Dump':      { id: 'T1003.003', tactic: 'Credential Access' },
    'SAM Database Access':                   { id: 'T1003.002', tactic: 'Credential Access' },
    'LSASS Memory Dump via LOLBin':          { id: 'T1003.001', tactic: 'Credential Access' },
    'Mimikatz Credential Dumping':           { id: 'T1003.001', tactic: 'Credential Access' },
    'Multi-Asset Coordinated Attack':        { id: 'T1078',     tactic: 'Defense Evasion' },
    'Repeated Malicious Indicator':          { id: 'T1078',     tactic: 'Defense Evasion' },
    'Connection from Known Malicious IP':    { id: 'T1071.001', tactic: 'Command and Control' },
    'Suspicious Account Creation':           { id: 'T1136.001', tactic: 'Persistence' },
    'New Account Creation':                  { id: 'T1136.001', tactic: 'Persistence' },
    'ACS Partial Detection':                 { id: 'T0000',     tactic: 'Unknown' },
    'SSH Authentication Failure':            { id: 'T1110.001', tactic: 'Credential Access' },
    'Repeated SSH Authentication Failure':   { id: 'T1110.001', tactic: 'Credential Access' },
    'Mass Authentication Attack':            { id: 'T1110.001', tactic: 'Credential Access' },
    'Privilege Escalation Detected':         { id: 'T1078',     tactic: 'Defense Evasion' },
    'Remote File Download via Command Line': { id: 'T1105',     tactic: 'Command and Control' },
    'Obfuscated Command Execution':          { id: 'T1027',     tactic: 'Defense Evasion' },
    'Privilege Abuse via Sudo Shell':        { id: 'T1548.003', tactic: 'Privilege Escalation' },
    'Cloud IAM Privilege Escalation':        { id: 'T1098',     tactic: 'Privilege Escalation' },
    'Cloud Role Assumption Failure':         { id: 'T1078.004', tactic: 'Defense Evasion' },
    'Suspicious Cloud Data Access':          { id: 'T1530',     tactic: 'Collection' },
    'Credential Resource Access':            { id: 'T1003',     tactic: 'Credential Access' },
    'Lateral Movement Candidate':            { id: 'T1021',     tactic: 'Lateral Movement' },
    'High-Volume Cloud Data Access':         { id: 'T1530',     tactic: 'Collection' },
    'Partial Detection — Unknown Log Format': { id: 'T0000',    tactic: 'Unknown' },
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

        // ACS vendor reconciliation — when ACS normalization is confident, override legacy alertType
        if (acsObject?.meta?.normalization_score >= 0.7 && acsObject?.meta?.vendor_origin !== 'unknown') {
          const vendorToAlertType = {
            windows:    'Windows Security Event',
            linux:      'Linux Security Event',
            cloudtrail: 'AWS CloudTrail',
          }
          const acsAlertType = vendorToAlertType[acsObject.meta.vendor_origin]
          if (acsAlertType && parsedAlert.alertType !== acsAlertType) {
            parsedAlert.alertType = acsAlertType
          }
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
        const normalizedUsername = acsObject?.acs_data?.user ?? parsedAlert.username
        const correlationUsername = normalizeUsernameForCorrelation(acsObject?.acs_data?.user ?? parsedAlert.username)


        const redisContextResult = await getRedisContext(ips, correlationUsername, safeSessionId)
        const redisHits    = redisContextResult?.hits ?? null
        const redisPatterns = redisContextResult?.patterns ?? []
        const redisContext = buildRedisContextSummary(redisHits)

        // Filter redisContext to only include indicators present in the current alert
        // Prevents session history from contaminating current alert recommendations
        const currentAlertIPs = new Set(ips)
        const currentAlertUsers = new Set([correlationUsername, acsObject?.acs_data?.user ?? parsedAlert.username].filter(Boolean))

        const filteredRedisHits = (redisHits ?? []).filter(h => {
          if (h.key?.startsWith('ip:')) {
            const ip = h.key.slice(3)
            return currentAlertIPs.has(ip)
          }
          if (h.key?.startsWith('user:')) {
            const user = h.key.slice(5)
            return currentAlertUsers.has(user) ||
                   currentAlertUsers.has(normalizeUsernameForCorrelation(user))
          }
          return false
        })

        const narratorRedisContext = buildRedisContextSummary(filteredRedisHits)

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

        const signals      = getSignals(parsedAlert, enrichmentJudgment, redisHits, acsObject)
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
        const normScore = acsObject?.meta?.normalization_score ?? null
        if (normScore !== null) {
          let normAdj = 0
          if (normScore < 0.3)      normAdj = -30
          else if (normScore < 0.5) normAdj = -15
          else if (normScore >= 0.9) normAdj = 5
          if (normAdj !== 0) {
            finalVerdict.confidence = Math.max(0, Math.min(100, finalVerdict.confidence + normAdj))
            finalVerdict.decision_trace.push({ type: 'penalty', label: `Normalization score ${normScore} — confidence ${normAdj > 0 ? '+' : ''}${normAdj}`, value: normAdj, normalizationScore: normScore })
          }
        }

        // FIELD COHERENCE SCORING
        // Penalizes ACS objects where the event_type is present but expected companion fields are missing
        // Prevents normalization score inflation from single-field population
        if (acsObject?.acs_data) {
          const acs = acsObject.acs_data
          const eventType = acs.event_type

          const coherenceExpectations = {
            auth:      ['user', 'src_ip'],
            process:   ['command_line', 'user'],
            privilege: ['user', 'resource'],
            network:   ['src_ip', 'dest_ip'],
          }

          const expectedFields = coherenceExpectations[eventType]
          if (expectedFields && eventType !== 'unknown') {
            const presentCount = expectedFields.filter(f => acs[f] !== null && acs[f] !== undefined && acs[f] !== 'unknown').length
            const coherenceRatio = presentCount / expectedFields.length

            if (coherenceRatio === 0) {
              const penalty = 20
              finalVerdict.confidence = Math.max(0, finalVerdict.confidence - penalty)
              finalVerdict.decision_trace.push({
                type: 'penalty',
                label: `Field incoherence — ${eventType} event with no expected companion fields, confidence -${penalty}`,
                value: -penalty,
                event_type: eventType,
                missing: expectedFields
              })
            } else if (coherenceRatio < 0.5) {
              const penalty = 10
              finalVerdict.confidence = Math.max(0, finalVerdict.confidence - penalty)
              finalVerdict.decision_trace.push({
                type: 'penalty',
                label: `Field incoherence — ${eventType} event missing most companion fields, confidence -${penalty}`,
                value: -penalty,
                event_type: eventType,
                missing: expectedFields.filter(f => !acs[f] || acs[f] === 'unknown')
              })
            }
          }
        }

        // SIGNAL COHERENCE PENALTY
        // When behavioral signals point to unrelated MITRE tactics, confidence is reduced
        // Coherent evidence (multiple signals, same technique) is more credible than scattered evidence
        const behavioralSignalsWithMitre = (finalVerdict.signals ?? [])
          .filter(s => s.signal_layer === 'behavioral' && s.mitre)

        if (behavioralSignalsWithMitre.length >= 2) {
          const mitreTactics = new Set(
            behavioralSignalsWithMitre.map(s => {
              const tacticMap = {
                'T1110': 'CredentialAccess', 'T1110.001': 'CredentialAccess', 'T1110.003': 'CredentialAccess',
                'T1003': 'CredentialAccess', 'T1003.001': 'CredentialAccess', 'T1003.002': 'CredentialAccess',
                'T1021': 'LateralMovement', 'T1021.001': 'LateralMovement',
                'T1078': 'DefenseEvasion', 'T1078.004': 'DefenseEvasion',
                'T1105': 'CommandControl', 'T1027': 'DefenseEvasion',
                'T1548': 'PrivilegeEscalation', 'T1548.003': 'PrivilegeEscalation',
                'T1053': 'Persistence', 'T1053.005': 'Persistence',
                'T1204': 'Execution', 'T1204.002': 'Execution',
                'T1059': 'Execution', 'T1059.001': 'Execution',
                'T1530': 'Collection', 'T1098': 'PrivilegeEscalation',
                'T1070': 'DefenseEvasion', 'T1070.001': 'DefenseEvasion',
                'T1136': 'Persistence', 'T1136.001': 'Persistence',
              }
              return tacticMap[s.mitre] ?? 'Unknown'
            })
          )

          const hasUnknownTactic = mitreTactics.has('Unknown')
          mitreTactics.delete('Unknown')

          if (mitreTactics.size >= 3) {
            const penalty = 15
            finalVerdict.confidence = Math.max(0, finalVerdict.confidence - penalty)
            finalVerdict.decision_trace.push({
              type: 'penalty',
              label: `Signal incoherence — ${mitreTactics.size} unrelated MITRE tactics detected, confidence -${penalty}`,
              value: -penalty,
              tactics: [...mitreTactics]
            })
          } else if (mitreTactics.size === 2 && !hasUnknownTactic) {
            const penalty = 5
            finalVerdict.confidence = Math.max(0, finalVerdict.confidence - penalty)
            finalVerdict.decision_trace.push({
              type: 'penalty',
              label: `Signal divergence — ${mitreTactics.size} different MITRE tactics, confidence -${penalty}`,
              value: -penalty,
              tactics: [...mitreTactics]
            })
          }
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
                narratorRedisContext,
                isActiveCampaign,
                uniqueAssetCount,
                frequencyMultiplier,
                finalVerdict,
                acsObject
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
          recommendations: (() => {
            const triageHost = acsObject?.acs_data?.host ?? parsedAlert.asset ?? 'AFFECTED_HOST'
            return [
              `Investigate ${triageHost} for suspicious activity`,
              `Review logs for ${acsObject?.acs_data?.user ?? parsedAlert.username ?? 'involved accounts'}`,
              `Check network connections from ${triageHost}`,
              'Escalate to senior analyst if indicators persist',
              'Document findings and preserve evidence before remediation'
            ]
          })(),
          recommendation_provenance: ['behavioral_heuristic','forensic','forensic','behavioral_heuristic','forensic'],
          reasoning: `Deterministic engine classified this alert as ${finalVerdict.classification} with ${finalVerdict.severity} severity. ${typeof finalVerdict.decision_trace[0] === 'object' ? finalVerdict.decision_trace[0].label : finalVerdict.decision_trace[0]}. ${typeof finalVerdict.decision_trace[1] === 'object' ? finalVerdict.decision_trace[1].label : finalVerdict.decision_trace[1]}. Immediate investigation of ${acsObject?.acs_data?.host ?? parsedAlert.asset ?? 'the affected asset'} is recommended.`
        }

        const narrator = narratorOutput ?? narratorFallback

        const triage = {
          severity:          finalVerdict.severity,
          classification:    finalVerdict.classification,
          confidence:        finalVerdict.confidence,
          asset_is_critical: finalVerdict.asset_is_critical,
          evidence:          finalVerdict.evidence,
          affected_asset:    (() => {
            // Priority 1: ACS normalizer host (most reliable cross-vendor), then parser asset
            const acsHostPrimary = acsObject?.acs_data?.host
            if (acsHostPrimary && acsHostPrimary !== 'UNKNOWN' && acsHostPrimary.length > 0) return acsHostPrimary
            if (parsedAlert.asset && parsedAlert.asset !== 'UNKNOWN') return parsedAlert.asset
            if (parsedAlert.allAssets) {
              const first = parsedAlert.allAssets.split(',')[0]?.trim()
              if (first && first !== 'UNKNOWN') return first
            }
            // Priority 1b: ACS normalizer extracted host or CloudTrail target user
            const acsHost = acsObject?.acs_data?.host
            if (acsHost && acsHost !== 'UNKNOWN' && acsHost.length > 0) return acsHost
            const acsTargetUser = acsObject?.acs_data?.target_user
            if (acsTargetUser && acsTargetUser.length > 0) return `IAM:${acsTargetUser}`
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
            const usernameForHost = acsObject?.acs_data?.user ?? parsedAlert.username
            if (usernameForHost && usernameForHost !== 'system' && !usernameForHost.includes('$') && usernameForHost.length > 3) {
              return `HOST:${usernameForHost.toUpperCase()}`
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
            return filtered.length > 0 ? filtered : (parsedAlert.allEventCodes ? [`EventCode=${parsedAlert.allEventCodes}`, `Asset=${acsObject?.acs_data?.host ?? parsedAlert.asset ?? 'UNKNOWN'}`, `User=${acsObject?.acs_data?.user ?? parsedAlert.username ?? 'UNKNOWN'}`] : raw)
          })(),
          mitre_id: (() => {
            if (finalVerdict.deterministicMitre) return finalVerdict.deterministicMitre
            const classificationMitre = getClassificationMitre(finalVerdict.classification)?.id
            if (classificationMitre) return classificationMitre
            // Only use narrator MITRE if classification is not UNKNOWN
            if (finalVerdict.classification !== 'UNKNOWN' && narrator?.mitre_id && narrator.mitre_id !== 'T0000') return narrator.mitre_id
            return null
          })(),
          mitre_name: (() => {
            if (finalVerdict.deterministicMitre) return getMitreName(finalVerdict.deterministicMitre)
            const fb = getClassificationMitre(finalVerdict.classification)
            if (fb) return getMitreName(fb.id) ?? finalVerdict.classification
            if (finalVerdict.classification !== 'UNKNOWN' && narrator?.mitre_name) return narrator.mitre_name
            return finalVerdict.classification
          })(),
          tactic: (() => {
            const classificationTactic = getClassificationMitre(finalVerdict.classification)?.tactic
            if (classificationTactic) return classificationTactic
            if (finalVerdict.classification !== 'UNKNOWN' && narrator?.tactic && narrator.tactic !== 'Unknown') return narrator.tactic
            return 'Unknown'
          })(),
          mitre_tactic: (() => {
            const classificationTactic = getClassificationMitre(finalVerdict.classification)?.tactic
            if (classificationTactic) return classificationTactic
            if (finalVerdict.classification !== 'UNKNOWN' && narrator?.mitre_tactic && narrator.mitre_tactic !== 'Unknown') return narrator.mitre_tactic
            return 'Unknown'
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
          `Run: net user ${acsObject?.acs_data?.user ?? parsedAlert.username ?? 'AFFECTED_USER'} /domain — check account status`,
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
        // Use the behavioral dominant signal for sanity check, not signals[0]
        // signals[0] may be an enrichment signal that doesn't reflect the classification source
        const dominantSignalRule = (
          finalVerdict.signals?.find(s => s.signal_layer === 'behavioral' && s.category === 'behavioral')
          ?? finalVerdict.signals?.[0]
        )?.rule
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
        await writeRedisContext(ips, correlationUsername, { ...triage, allAffectedAssets }, caseId, safeSessionId)

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
            signals:                  (finalVerdict.signals ?? []).map(s => ({ rule: s.rule, label: s.label, severity: s.severity, category: s.category, signal_layer: s.signal_layer, ...(s.mitre ? { mitre: s.mitre } : {}) })),
            correlationPatterns:      redisPatterns,
            acs:                      acsObject,
            normalizationScore:       acsObject?.meta?.normalization_score ?? null,
            vendorOrigin:             acsObject?.meta?.vendor_origin ?? 'unknown',
            behavioralSignalCount:    (finalVerdict.signals ?? []).filter(s => s.signal_layer === 'behavioral').length,
            enrichmentSignalCount:    (finalVerdict.signals ?? []).filter(s => s.signal_layer === 'enrichment').length,
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