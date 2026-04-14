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
  // Strip DOMAIN\ prefix (Windows SAM format)
  let normalized = username.replace(/^[^\\]+\\/, '')
  // Strip @domain suffix (UPN format)
  normalized = normalized.replace(/@.+$/, '')
  normalized = normalized.toLowerCase().trim()
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
    ['WorkstationName','ComputerName','Computer','Hostname','host','computer','device'],
    /(?:WorkstationName|ComputerName|Computer|Hostname|host)[=:\s]+(\S+)/i
  )

  const allAssets = (() => {
    const fromText = (text.match(/(?:WorkstationName|ComputerName|Computer|Hostname)[=:\s]+(\S+)/gi) ?? [])
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
    processName:   get(['NewProcessName','ProcessName','Image','process_name'], /(?:New Process Name|NewProcessName|(?<![Pp]arent\s*)ProcessName|Image)[=:\s]+(.+?)(?:\r?\n|$)/i),
    commandLine:   get(['CommandLine','ProcessCommandLine','command_line','Process Command Line'], /(?:Process Command Line|CommandLine|ProcessCommandLine)[=:\s]+(.+?)(?:\r?\n|$)/i),
    asset:         rawAsset ? normalizeAsset(rawAsset) : null,
    allAssets,
    allEventCodes,
    count:         get(['Count','count'], /Count[=:\s]+(\d+)/i),
    fileHash:      get(['MD5','SHA1','SHA256','Hashes'], /(?:MD5|SHA1|SHA256|Hashes)[=:\s]+([a-fA-F0-9]{32,64})/i),
    parentProcess: get(['ParentProcessName','ParentImage'], /(?:Parent Process Name|ParentProcessName|ParentImage)[=:\s]+(.+?)(?:\r?\n|$)/i),
    serviceName:   get(['ServiceName'], /ServiceName[=:\s]+(\S+)/i),
    serviceFileName: get(
      ['ServiceFileName', 'ImagePath'],
      /(?:ServiceFileName|ImagePath)[=:\s]+(.+?)(?:\r?\n|$)/i
    ),
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
// ── DECISION ENGINE ───────────────────────────────────────────────────────────

// Provenance independence gate — declared pair variant.
// fieldA, fieldB: string names of acs_data fields (e.g. 'action', 'user').
// Returns true only when both fields are populated (non-null, non-empty, non-'unknown'),
// have non-null sources, have distinct sources, and are not both 'derived:event_id_table'.
function checkIndependencePair(acs, fieldA, fieldB) {
  const a = acs?.[fieldA]
  const b = acs?.[fieldB]
  if (!a?.value || !b?.value) return false
  if (a.value === 'unknown' || b.value === 'unknown') return false
  if (!a.source || !b.source) return false
  if (a.source === b.source) return false
  if (a.source === 'derived:event_id_table' && b.source === 'derived:event_id_table') return false
  return true
}

// OR variant — signal has two valid evidence paths; either pair suffices.
function checkIndependencePairOr(acs, pairA, pairB) {
  return checkIndependencePair(acs, pairA[0], pairA[1])
      || checkIndependencePair(acs, pairB[0], pairB[1])
}

// Direct variant — takes { value, source } objects directly (for resource proxy fields
// constructed inline rather than named acs_data keys).
function checkIndependencePairDirect(fieldA, fieldB) {
  if (!fieldA?.value || !fieldB?.value) return false
  if (fieldA.value === 'unknown' || fieldB.value === 'unknown') return false
  if (!fieldA.source || !fieldB.source) return false
  if (fieldA.source === fieldB.source) return false
  if (fieldA.source === 'derived:event_id_table' && fieldB.source === 'derived:event_id_table') return false
  return true
}

/**
 * ARBITER ARCHITECTURAL BOUNDARY — SINGLE-EVENT TRIAGE MODEL
 *
 * ARBITER is designed for deep single-event triage, not log aggregation.
 * Each submission is treated as one logical event. When multi-line input
 * is submitted, ARBITER extracts the primary detectable primitive from
 * the first parseable event and produces a single verdict.
 *
 * This is a design statement, not a limitation:
 * - SIEMs aggregate. ARBITER triages with depth and traceability.
 * - These are different tools for different purposes.
 * - A single-event model enables provenance tracking, independence
 *   gate enforcement, and deterministic signal derivation that
 *   volume-based aggregation cannot provide.
 *
 * Consequence for multi-line logs:
 * - Only the first extractable command-line primitive produces signals.
 * - Analysts submitting multi-event sequences (e.g. bash execution
 *   chains) should submit each event separately for individual verdicts.
 * - This boundary is intentional and documented as scope, not a gap.
 *
 * This constraint is tracked as Issue 10.3 in the architectural map.
 */
function getSignals(parsed, enrichmentJudgment, redisHits, acsObject = null, internalFailureHits = null) {
  const signals = []

  const asset = (acsObject?.acs_data?.host?.value ?? parsed.asset ?? '').toUpperCase()
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
      signals.push({ rule: 'ASSET_CRITICAL', classification: 'Critical Asset Targeted', label: cp.label, severity: cp.severity, confidence: cp.confidence, weight: cp.weight, evidence: [`asset=${asset || parsed.allAssets}`], category: 'asset', source: 'windows-eventid', signal_layer: 'asset', explanation_weight: cp.severity === 'CRITICAL' ? 'high' : 'medium', confidence_boost: cp.severity === 'CRITICAL' ? 15 : 10 })
      break
    }
  }

  const count = parseInt(acsObject?.acs_data?.count?.value ?? parsed.count ?? '0', 10)
  const eventIds = (parsed.allEventCodes ?? parsed.eventId ?? '').split(',').map(s => s.trim())

  if (eventIds.includes('4625') || eventIds.includes('4771')) {
    if (count > 100) signals.push({ rule: 'BRUTE_FORCE_EXTREME', classification: 'Brute Force Attack', label: 'Extreme brute force volume', severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`EventCode=4625`, `Count=${count}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1110.001', explanation_weight: 'high', confidence_boost: 15 })
    else if (count > 20) signals.push({ rule: 'BRUTE_FORCE_HIGH', classification: 'Brute Force Attack', label: 'High-volume brute force', severity: 'CRITICAL', confidence: 90, weight: 4, evidence: [`EventCode=4625`, `Count=${count}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1110.001', explanation_weight: 'high', confidence_boost: 15 })
    else if (count > 5) signals.push({ rule: 'BRUTE_FORCE_MEDIUM', classification: 'Password Spraying', label: 'Repeated failed logons', severity: 'HIGH', confidence: 75, weight: 3, evidence: [`EventCode=4625`, `Count=${count}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1110.001', explanation_weight: 'medium', confidence_boost: 10 })
    else signals.push({ rule: 'LOGON_FAILURE_LOW', classification: 'Failed Logon', label: 'Low-count logon failure', severity: 'LOW', confidence: 70, weight: 1, evidence: [`EventCode=4625`, `Count=${count || '1'}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1110', explanation_weight: 'low', confidence_boost: 5 })
  }

  const cmdLine = (acsObject?.acs_data?.command_line?.value ?? parsed.commandLine ?? '').toLowerCase()
  const procName = (acsObject?.acs_data?.process_name?.value ?? parsed.processName ?? '').toLowerCase()
  const parentProc = (
    acsObject?.acs_data?.parent_process?.value
    ?? parsed.parentProcess
    ?? ''
  ).toLowerCase()

  // CERTUTIL download cradle
  if (procName.includes('certutil')
      && /-urlcache|-split|-f\s/i.test(cmdLine)
      && checkIndependencePair(acsObject?.acs_data, 'command_line', 'process_name')) {
    signals.push({ rule: 'LOLBIN_CERTUTIL_DOWNLOAD', classification: 'Malicious File Download via LOLBin', label: 'certutil used as download cradle', severity: 'HIGH', confidence: 92, weight: 5, evidence: [`ProcessName=${procName}`, `CommandLine=${cmdLine.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'behavioral', mitre: 'T1105', explanation_weight: 'medium', confidence_boost: 10, independence_pair: ['command_line', 'process_name'] })
  }

  // CERTUTIL suspicious path — independent of download flags
  // Fires when certutil writes decoded/processed content to
  // user-writable or temp directories regardless of technique
  if (procName.includes('certutil')
      && /users\\public|windows\\temp|programdata/i.test(cmdLine)
      && checkIndependencePair(acsObject?.acs_data, 'command_line', 'process_name')) {
    signals.push({ rule: 'LOLBIN_CERTUTIL_SUSPICIOUS_PATH', classification: 'LOLBin Staging to Suspicious Path', label: 'certutil writing to suspicious path', severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`CommandLine=${cmdLine.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'behavioral', mitre: 'T1105', explanation_weight: 'high', confidence_boost: 15, independence_pair: ['command_line', 'process_name'] })
  }

  if (procName.includes('mshta')
      && /http[s]?:\/\//i.test(cmdLine)
      && checkIndependencePair(acsObject?.acs_data, 'command_line', 'process_name'))
    signals.push({ rule: 'LOLBIN_MSHTA_REMOTE', classification: 'Remote Script Execution via mshta', label: 'mshta executing remote content', severity: 'HIGH', confidence: 90, weight: 5, evidence: [`ProcessName=${procName}`, `CommandLine=${cmdLine.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'behavioral', mitre: 'T1218.005', explanation_weight: 'medium', confidence_boost: 10, independence_pair: ['command_line', 'process_name'] })

  const officeParents = ['winword.exe','excel.exe','powerpnt.exe','outlook.exe','onenote.exe','mspub.exe','msaccess.exe','acrord32.exe','acrobat.exe','foxitreader.exe']
  const lolbins = ['mshta.exe','wscript.exe','cscript.exe','powershell.exe','cmd.exe','certutil.exe','regsvr32.exe','rundll32.exe']
  if (
    officeParents.some(p => parentProc.includes(p)) &&
    lolbins.some(l => procName.includes(l)) &&
    checkIndependencePair(acsObject?.acs_data, 'parent_process', 'process_name')
  ) {
    signals.push({ rule: 'OFFICE_MACRO_DROPPER', classification: 'Macro-based Dropper Execution', label: 'Office application spawning LOLBin', severity: 'CRITICAL', confidence: 98, weight: 5, evidence: [`ParentProcess=${parentProc}`, `ProcessName=${procName}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'behavioral', mitre: 'T1204.002', explanation_weight: 'high', confidence_boost: 15, independence_pair: ['parent_process', 'process_name'] })
  }

  // BROWSER SPAWN SCRIPTING — browser process spawning scripting host or LOLBin.
  // Threat model: drive-by compromise or malicious download execution chain.
  // Weight 3 (not 5): browser false positive surface is non-trivial — enterprise
  // DLP agents and some browser extensions legitimately spawn subprocesses.
  // This keeps the signal TRACE_REQUIRED standalone while remaining eligible
  // to compound to SURFACE_SAFE when co-firing with a weight-4 behavioral
  // signal (e.g. POWERSHELL_ENCODED). Confidence 65 is calibrated between
  // ACS_CLOUD_PRIVILEGE_ESCALATION_ATTEMPT (72) and ACS_LATERAL_MOVEMENT_CANDIDATE (50).
  const browserParents = ['chrome.exe','msedge.exe','microsoftedge.exe','firefox.exe','iexplore.exe']
  if (
    browserParents.some(p => parentProc.includes(p)) &&
    lolbins.some(l => procName.includes(l)) &&
    checkIndependencePair(acsObject?.acs_data, 'parent_process', 'process_name')
  ) {
    signals.push({ rule: 'BROWSER_SPAWN_SCRIPTING', classification: 'Browser Process Spawning Scripting Host', label: `Browser spawned scripting process: ${parentProc.split('\\').pop()} → ${procName.split('\\').pop()}`, severity: 'HIGH', confidence: 65, weight: 3, evidence: [`ParentProcess=${parentProc}`, `ProcessName=${procName}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'behavioral', mitre: 'T1189', independence_pair: ['parent_process', 'process_name'] })
  }

  if (procName.includes('powershell')
      && /-enc\b|-encodedcommand/i.test(cmdLine)
      && checkIndependencePair(acsObject?.acs_data, 'command_line', 'process_name'))
    signals.push({ rule: 'POWERSHELL_ENCODED', classification: 'Encoded PowerShell Execution', label: 'Encoded PowerShell command', severity: 'HIGH', confidence: 85, weight: 4, evidence: [`ProcessName=${procName}`, `CommandLine=${cmdLine.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'behavioral', mitre: 'T1059.001', explanation_weight: 'medium', confidence_boost: 10, independence_pair: ['command_line', 'process_name'] })

  if (eventIds.includes('4698') || eventIds.includes('4702')) {
    // task_content is now an ACS field — prefer it over legacy fallbacks
    // Falls back to command_line (also ACS) when task_content is absent
    const taskContent = (
      acsObject?.acs_data?.task_content?.value
      ?? acsObject?.acs_data?.command_line?.value
      ?? parsed.taskContent
      ?? parsed.commandLine
      ?? parsed.taskName
      ?? ''
    ).toLowerCase()

    // Determine which field pair is available for independence check
    const hasTaskContentField = !!(acsObject?.acs_data?.task_content?.value)
    const taskPair = hasTaskContentField
      ? ['task_content', 'task_name']
      : ['command_line', 'task_name']
    const hasTaskGate = checkIndependencePair(acsObject?.acs_data, taskPair[0], taskPair[1])

    const isCradlePattern = /iex|invoke-expression|downloadstring|-enc|certutil/i.test(taskContent)
    if (isCradlePattern && hasTaskGate) {
      signals.push({ rule: 'SCHEDULED_TASK_CRADLE', classification: 'Malicious Scheduled Task Persistence', label: 'Scheduled task with download cradle', severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`EventCode=4698`, `TaskName=${parsed.taskName}`, `Content=${taskContent.slice(0,60)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1053.005', explanation_weight: 'high', confidence_boost: 15, independence_pair: taskPair })
    } else {
      // Pattern matched but independence gate failed, or pattern not matched — benign fallback
      signals.push({ rule: 'SCHEDULED_TASK_CREATED', classification: 'Scheduled Task Created', label: 'Scheduled task created', severity: 'MEDIUM', confidence: 60, weight: 2, evidence: [`EventCode=4698`, `TaskName=${parsed.taskName}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1053.005', explanation_weight: 'low', confidence_boost: 5 })
    }
  }

  if (eventIds.includes('4697') || eventIds.includes('7045')) {
    const svcPath = (
      acsObject?.acs_data?.service_path?.value
      ?? parsed.serviceFileName
      ?? acsObject?.acs_data?.command_line?.value
      ?? parsed.commandLine
      ?? acsObject?.acs_data?.object_name?.value
      ?? parsed.objectName
      ?? ''
    ).toLowerCase()
    if (
      /users\\public|windows\\temp|programdata|appdata/i.test(svcPath) &&
      checkIndependencePair(acsObject?.acs_data, 'service_name', 'service_path')
    ) {
      signals.push({ rule: 'SERVICE_SUSPICIOUS_PATH', classification: 'Suspicious Service Installation', label: 'Service binary in suspicious path', severity: 'CRITICAL', confidence: 93, weight: 5, evidence: [`EventCode=${eventIds.includes('7045') ? '7045' : '4697'}`, `ServiceName=${parsed.serviceName}`, `Path=${svcPath.slice(0,60)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'behavioral', independence_pair: ['service_name', 'service_path'], mitre: 'T1543.003', explanation_weight: 'high', confidence_boost: 15 })
    }
  }

  if (eventIds.includes('1102') || eventIds.includes('4719'))
    signals.push({ rule: 'AUDIT_LOG_CLEARED', classification: 'Security Log Tampering', label: 'Security audit log cleared', severity: 'CRITICAL', confidence: 98, weight: 5, evidence: [`EventCode=${eventIds.includes('1102') ? '1102' : '4719'}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1070.001', explanation_weight: 'high', confidence_boost: 15 })

  if (eventIds.includes('4720')) {
    const targetUser = (acsObject?.acs_data?.target_user?.value ?? parsed.targetUsername ?? acsObject?.acs_data?.user?.value ?? parsed.username ?? '').toLowerCase()
    const isSuspiciousName = /backdoor|hack|persist|0day|temp|svc_|_svc|admin_/i.test(targetUser)
    if (isSuspiciousName) {
      signals.push({ rule: 'ACCOUNT_CREATED_SUSPICIOUS', classification: 'Suspicious Account Creation', label: `Suspicious account created: ${targetUser}`, severity: 'CRITICAL', confidence: 95, weight: 5, evidence: [`EventCode=4720`, `TargetUserName=${targetUser}`, `CreatedBy=${acsObject?.acs_data?.user?.value ?? parsed.username}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1136.001', explanation_weight: 'high', confidence_boost: 15 })
    } else {
      signals.push({ rule: 'ACCOUNT_CREATED', classification: 'New Account Creation', label: 'New user account created', severity: 'MEDIUM', confidence: 65, weight: 3, evidence: [`EventCode=4720`, `TargetUserName=${targetUser}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'enrichment', mitre: 'T1136.001', explanation_weight: 'low', confidence_boost: 5 })
    }
  }

  if (eventIds.includes('4663') || eventIds.includes('4656')) {
    const obj = (acsObject?.acs_data?.object_name?.value ?? parsed.objectName ?? '').toLowerCase()
    if (obj.includes('ntds.dit')
        && checkIndependencePair(acsObject?.acs_data, 'object_name', 'event_type'))
      signals.push({ rule: 'NTDS_ACCESS', classification: 'Active Directory Credential Dump', label: 'ntds.dit accessed', severity: 'CRITICAL', confidence: 99, weight: 5, evidence: [`EventCode=4663`, `ObjectName=${obj}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'behavioral', mitre: 'T1003.003', explanation_weight: 'high', confidence_boost: 15, independence_pair: ['object_name', 'event_type'] })
    else if (obj.includes('sam')
             && checkIndependencePair(acsObject?.acs_data, 'object_name', 'event_type'))
      signals.push({ rule: 'SAM_ACCESS', classification: 'SAM Database Access', label: 'SAM database accessed', severity: 'CRITICAL', confidence: 96, weight: 5, evidence: [`EventCode=4663`, `ObjectName=${obj}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'behavioral', mitre: 'T1003.002', explanation_weight: 'high', confidence_boost: 15, independence_pair: ['object_name', 'event_type'] })
  }

  if (procName && cmdLine) {
    const isRundll32 = procName.includes('rundll32')
    const isLsassDump = /comsvcs|minidump|lsass/i.test(cmdLine)
    const isMimikatz = /mimikatz|sekurlsa|privilege::debug/i.test(cmdLine)
    if (isRundll32
        && isLsassDump
        && checkIndependencePair(acsObject?.acs_data, 'command_line', 'process_name')) {
      signals.push({ rule: 'LSASS_DUMP_RUNDLL32', classification: 'LSASS Memory Dump via LOLBin', label: 'LSASS memory dump via rundll32/comsvcs', severity: 'CRITICAL', confidence: 99, weight: 5, evidence: [`ProcessName=${procName}`, `CommandLine=${cmdLine.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'behavioral', mitre: 'T1003.001', explanation_weight: 'high', confidence_boost: 15, independence_pair: ['command_line', 'process_name'] })
    }
    // MIMIKATZ requires independently-sourced command_line AND process_name — prevents false
    // positives from logs where both fields are derived from the same EventID lookup table
    if (isMimikatz && checkIndependencePair(acsObject?.acs_data, 'command_line', 'process_name')) {
      signals.push({ rule: 'MIMIKATZ_DETECTED', classification: 'Mimikatz Credential Dumping', label: 'Mimikatz credential dumping detected', severity: 'CRITICAL', confidence: 99, weight: 5, evidence: [`CommandLine=${cmdLine.slice(0,80)}`], category: 'behavioral', source: 'windows-eventid', signal_layer: 'behavioral', mitre: 'T1003.001', explanation_weight: 'high', confidence_boost: 15, independence_pair: ['command_line', 'process_name'] })
    }
  }

  const verdict = enrichmentJudgment?.judgment
  if (verdict === 'CONFIRMED_MALICIOUS') signals.push({ rule: 'ENRICHMENT_CONFIRMED_MALICIOUS', classification: 'Connection from Known Malicious IP', label: 'IP confirmed malicious', severity: 'HIGH', confidence: 80, weight: 3, evidence: [`enrichmentVerdict=CONFIRMED_MALICIOUS`], category: 'enrichment', source: 'windows-eventid', signal_layer: 'enrichment', mitre: null, explanation_weight: 'medium', confidence_boost: 10 })
  else if (verdict === 'SUSPICIOUS') signals.push({ rule: 'ENRICHMENT_SUSPICIOUS', classification: 'Connection from Suspicious IP', label: 'IP flagged suspicious', severity: 'MEDIUM', confidence: 60, weight: 2, evidence: [`enrichmentVerdict=SUSPICIOUS`], category: 'enrichment', source: 'windows-eventid', signal_layer: 'enrichment', mitre: null, explanation_weight: 'low', confidence_boost: 5 })
  else if (verdict === 'CLEAN') signals.push({ rule: 'ENRICHMENT_CLEAN', classification: 'Network Connection — Clean Source', label: 'IP clean across all sources', severity: 'LOW', confidence: 50, weight: 1, evidence: [`enrichmentVerdict=CLEAN`], category: 'enrichment', source: 'windows-eventid', signal_layer: 'enrichment', mitre: null, explanation_weight: 'low', confidence_boost: 5 })

  if (redisHits?.length > 0) {
    const maxCount = redisHits.reduce((max, h) => Math.max(max, h.count ?? 0), 0)
    const uniqueAssets = new Set(redisHits.flatMap(h => h.assets ?? [])).size
    if (maxCount >= 2 && uniqueAssets >= 2) signals.push({ rule: 'CORRELATED_INDICATOR_ACTIVITY', classification: 'Multi-Asset Coordinated Attack', label: `Active campaign — ${maxCount} hits across ${uniqueAssets} assets`, severity: 'CRITICAL', confidence: 90, weight: 5, frequency: true, evidence: [`redisHits=${maxCount}`, `uniqueAssets=${uniqueAssets}`], category: 'temporal', source: 'redis', signal_layer: 'temporal', mitre: 'T1078', explanation_weight: 'high', confidence_boost: 15 })
    else if (maxCount >= 2) signals.push({ rule: 'REPEATED_INDICATOR', classification: 'Repeated Malicious Indicator', label: `Indicator seen ${maxCount}× in last 24h`, severity: 'HIGH', confidence: 75, weight: 3, frequency: true, evidence: [`redisHits=${maxCount}`], category: 'temporal', source: 'redis', signal_layer: 'temporal', mitre: 'T1078', explanation_weight: 'medium', confidence_boost: 10 })
  }

  // Successful authentication from confirmed malicious source
  // Fires when: auth success + src_ip confirmed malicious by current
  // enrichment + Redis holds prior hits for this IP (count >= 2)
  // This is a state-change temporal signal — not a frequency signal
  const acsEventOutcome = acsObject?.acs_data?.event_outcome?.value
  const acsSrcIp = acsObject?.acs_data?.src_ip?.value
  const acsEventType = acsObject?.acs_data?.event_type?.value

  if (acsEventType === 'auth'
      && acsEventOutcome === 'success'
      && acsSrcIp
      && enrichmentJudgment?.judgment === 'CONFIRMED_MALICIOUS'
      && checkIndependencePair(acsObject.acs_data, 'event_outcome', 'src_ip')) {

    // Require prior Redis hits for this IP — confirms this is not
    // first-time appearance but a returning confirmed-malicious source
    const priorHits = (redisHits ?? []).find(h =>
      h.key && (h.key.includes(`ip:${acsSrcIp}`) || h.key === `ip:${acsSrcIp}`)
    )
    const priorCount = priorHits?.count ?? 0

    if (priorCount >= 2) {
      // State-change behavioral signal — fires when a confirmed malicious
      // source that has been seen before in this session (priorCount >= 2)
      // successfully authenticates. Classified as behavioral because the
      // detection is an observed authentication event, not a frequency
      // pattern. The Redis precondition is a confidence threshold, not
      // the detection mechanism.
      signals.push({
        rule: 'ACS_MALICIOUS_SOURCE_AUTH_SUCCESS',
        label: 'Successful authentication from confirmed malicious source',
        severity: 'CRITICAL',
        confidence: 90,
        weight: 5,
        evidence: [
          `event_outcome=success`,
          `src_ip=${acsSrcIp}`,
          `prior_hits=${priorCount}`,
          `enrichment=CONFIRMED_MALICIOUS`,
        ],
        category: 'behavioral',
        signal_layer: 'behavioral',
        frequency: false,
        mitre: 'T1078',
        independence_pair: ['event_outcome', 'src_ip'],
      })
    }
  }

  // ── ACS BEHAVIORAL SIGNALS ────────────────────────────────────────────────
  // These signals fire from acs_data only — vendor-agnostic, format-blind.
  // They run alongside existing EventID signals, not replacing them.
  // Priority: existing behavioral signals (weight 5) > ACS signals (weight 3-4)
  // to avoid double-counting.

  const acs = acsObject?.acs_data
  const acsVendor = acsObject?.meta?.vendor_origin ?? 'unknown'
  const normScore = acsObject?.meta?.normalization_score ?? 0

  // ── ACS value extraction — unwrap all { value, source } fields to plain values ──
  // acsv provides flat access; acsResource is the logical proxy for object/task/service/resource
  const acsv = acs ? {
    event_type:    acs.event_type?.value    ?? 'unknown',
    event_outcome: acs.event_outcome?.value ?? 'unknown',
    action:        acs.action?.value        ?? 'unknown',
    user:          acs.user?.value          ?? null,
    src_ip:        acs.src_ip?.value        ?? null,
    host:          acs.host?.value          ?? null,
    command_line:  acs.command_line?.value  ?? null,
    process_name:  acs.process_name?.value  ?? null,
    count:         acs.count?.value         ?? null,
    object_name:   acs.object_name?.value   ?? null,
    task_name:     acs.task_name?.value     ?? null,
    service_name:  acs.service_name?.value  ?? null,
    resource_name: acs.resource_name?.value ?? null,
    target_user:   acs.target_user?.value   ?? null,
    logon_type:    acs.logon_type?.value    ?? null,
  } : null
  const acsResource = acsv
    ? (acsv.object_name ?? acsv.task_name ?? acsv.service_name ?? acsv.resource_name ?? null)
    : null

  if (acsv && normScore >= 0.5) {

    // AUTH FAILURE — vendor agnostic brute force detection
    if (acsv.event_type === 'auth' && acsv.event_outcome === 'failure') {
      // Windows brute force is covered by BRUTE_FORCE_* EventID signals
      // (enrichment-behavioral tier). ACS behavioral signals are for
      // Linux and CloudTrail where EventID signals do not fire.
      if (acsVendor === 'windows') {
        // skip — double-fire suppressed
      } else {
        const acsCount = acsv.count ?? 1

        if (acsCount > 20
            && checkIndependencePairOr(
                 acsObject?.acs_data,
                 ['count', 'src_ip'],
                 ['count', 'event_outcome']
               )) {
          signals.push({ rule: 'ACS_AUTH_FAILURE_MASS', classification: 'Mass Authentication Attack', label: `Mass authentication failures (${acsCount}×) via ${acsVendor}`, severity: 'CRITICAL', confidence: 88, weight: 4, evidence: [`event_type=auth`, `event_outcome=failure`, `count=${acsCount}`, `src_ip=${acsv.src_ip ?? 'unknown'}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1110' })
        } else if (acsCount > 5
                   && checkIndependencePairOr(
                        acsObject?.acs_data,
                        ['count', 'src_ip'],
                        ['count', 'event_outcome']
                      )) {
          signals.push({ rule: 'ACS_AUTH_FAILURE_HIGH', classification: 'Repeated Authentication Failures', label: `Repeated authentication failures (${acsCount}×) via ${acsVendor}`, severity: 'HIGH', confidence: 75, weight: 3, evidence: [`event_type=auth`, `event_outcome=failure`, `count=${acsCount}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1110' })
        } else {
          // ACS_AUTH_FAILURE_LOW: (event_outcome, src_ip) independence pair.
          // Belt-and-suspenders: explicit Windows guard + independence gate.
          // Windows: both event_type and event_outcome share derived:event_id_table —
          // the gate alone correctly blocks it, but the vendor guard makes intent explicit.
          // Windows coverage is via LOGON_FAILURE_LOW (EventID-based).
          // CloudTrail auth failures are covered by purpose-built signals:
          // ACS_CLOUD_ROLE_ASSUMPTION_FAIL, ACS_AUTH_FAILURE_HIGH/MASS.
          // ACS_AUTH_FAILURE_LOW on CloudTrail adds ~7 points of confidence
          // contamination via supporting contribution without adding signal.
          if (acsVendor !== 'windows'
              && acsVendor !== 'cloudtrail'
              && checkIndependencePair(acs, 'event_outcome', 'src_ip')) {
            signals.push({ rule: 'ACS_AUTH_FAILURE_LOW', classification: 'Authentication Failure', label: `Authentication failure via ${acsVendor}`, severity: 'LOW', confidence: 55, weight: 2, evidence: [`event_type=auth`, `event_outcome=failure`, ...(acsv.src_ip ? [`src_ip=${acsv.src_ip}`] : [])], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1110', independence_pair: ['event_outcome', 'src_ip'] })
          }
        }
      }
    }

    // ACCOUNT DELETION — IAM/directory account removal (evidence destruction indicator)
    // Gate: action + user independently sourced
    if (acsv.event_type === 'privilege' && /deleteuser|deleterole|deletegroup/i.test(acsv.action ?? '') && checkIndependencePair(acs, 'action', 'user')) {
      signals.push({ rule: 'ACS_ACCOUNT_DELETION', classification: 'Account Deletion — Potential Evidence Destruction', label: `Account deletion detected: ${acsv.action} via ${acsVendor}`, severity: 'HIGH', confidence: 82, weight: 4, evidence: [`event_type=privilege`, `action=${acsv.action}`, `user=${acsv.user ?? 'unknown'}`, `target=${acsv.target_user ?? 'unknown'}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1531', independence_pair: ['action', 'user'] })
    }

    // PRIVILEGE ESCALATION — sudo, role assumption, policy changes
    // Gate: action + user independently sourced. On Windows: action=derived:event_id_table, user=raw:kv — independent.
    if (acsv.event_type === 'privilege' && acsv.action !== 'unknown' && checkIndependencePair(acs, 'action', 'user')) {
      signals.push({ rule: 'ACS_PRIVILEGE_ACTION', classification: 'Privilege Escalation Detected', label: `Privilege action detected: ${acsv.action} via ${acsVendor}`, severity: 'MEDIUM', confidence: 65, weight: 3, evidence: [`event_type=privilege`, `action=${acsv.action}`, `user=${acsv.user ?? 'unknown'}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1078', independence_pair: ['action', 'user'] })
    }

    // CREDENTIAL-SENSITIVE OBJECT ACCESS — fires without process creation context
    // Covers LSASS file access, SAM access, cloud IMDS credential theft, shadow/passwd
    if (acsResource) {
      const resource = acsResource.toLowerCase()
      const isSensitiveResource = /ntds\.dit|lsass|\/sam$|security-credentials|\.aws\/credentials|\/shadow$|\/passwd$|\/etc\/shadow|\/proc\/\d+\/mem|krbtgt|ntlm|secretsdump/i.test(resource)
      if (isSensitiveResource && !signals.some(s => s.rule === 'LSASS_DUMP_RUNDLL32' || s.rule === 'NTDS_ACCESS' || s.rule === 'SAM_ACCESS')) {
        signals.push({
          rule: 'ACS_OBJECT_ACCESS_SENSITIVE',
          classification: 'Credential Resource Access',
          label: `Sensitive credential resource accessed: ${acsResource}`,
          severity: 'HIGH',
          confidence: 78,
          weight: 4,
          evidence: [`event_type=${acsv.event_type}`, `resource=${acsResource}`, `user=${acsv.user ?? 'unknown'}`],
          category: 'enrichment',
          source: 'acs',
          signal_layer: 'enrichment',
          mitre: 'T1003'
        })
      }
    }

    // LATERAL MOVEMENT CANDIDATE — successful network logon from internal source to different host
    // Gate: src_ip + host independently sourced. Semantic: src_ip value must differ from host value.
    if (
      acsv.event_type === 'auth' &&
      acsv.event_outcome === 'success' &&
      (acsv.action === 'logon' || acsv.action === 'logon_explicit') &&
      acsv.src_ip &&
      acsv.host &&
      acs.src_ip?.value !== acs.host?.value &&
      checkIndependencePair(acs, 'src_ip', 'host')
    ) {
      const isInternalSrc = /^10\.|^172\.(1[6-9]|2\d|3[01])\.|^192\.168\./i.test(acsv.src_ip)
      if (isInternalSrc) {
        // Require prior session history for this src_ip.
        // First-time connections (routine deployments, monitoring agents,
        // authorized SSH) produce no session history and do not fire.
        // Only IPs that appeared previously in this session are candidates.
        // internalFailureHits tracks prior failed auth events from this
        // RFC1918 src_ip in the current session. It is populated by a
        // dedicated Redis read path (separate from the enrichment namespace
        // which excludes private IPs). A count >= 1 means this IP has
        // previously failed authentication in this session — a success
        // now from the same IP to a different host is a lateral movement
        // candidate.
        const lateralPriorCount = internalFailureHits?.count ?? 0

        if (lateralPriorCount >= 1) {
          signals.push({
            rule: 'ACS_LATERAL_MOVEMENT_CANDIDATE',
            classification: 'Lateral Movement Candidate',
            label: `Internal network logon: ${acsv.src_ip} → ${acsv.host}`,
            severity: 'MEDIUM',
            confidence: 50,
            weight: 2,
            evidence: [`event_type=auth`, `event_outcome=success`, `src_ip=${acsv.src_ip}`, `host=${acsv.host}`],
            category: 'behavioral',
            source: 'acs',
            signal_layer: 'behavioral',
            mitre: 'T1021',
            independence_pair: ['src_ip', 'host']
          })
        }
      }
    }

    // SUSPICIOUS DATA ACCESS — cloud storage read on sensitive resources
    // Gate: action + resource proxy independently sourced (resource proxy = resource_name ?? object_name ?? task_name ?? service_name)
    if (acsv.event_type === 'network' && /getobject|read|download|headobject|listobjects/i.test(acsv.action ?? '')
      && (enrichmentJudgment?.judgment === 'CONFIRMED_MALICIOUS'
          || enrichmentJudgment?.judgment === 'SUSPICIOUS')) {
      const acsResourceField = acs.resource_name ?? acs.object_name ?? acs.task_name ?? acs.service_name ?? { value: null, source: null }
      const resource = (acsResource ?? '').toLowerCase()
      const user = (acsv.user ?? '').toLowerCase()
      const sensitiveResource = /prod|financial|finance|secure|backup|secret|confidential|private|pii|credential|password|key/i.test(resource)
      const suspiciousUser = /contractor|temp|tmp|test|intern|vendor|external/i.test(user)

      if ((sensitiveResource || suspiciousUser) && checkIndependencePairDirect(acs.action, acsResourceField)) {
        // Recurrence suppression — if same user seen 3+ times in session
        // without other malicious indicators, downgrade to LOW to prevent alert fatigue
        const hasOtherMalicious = signals.some(s => s.rule === 'ENRICHMENT_CONFIRMED_MALICIOUS' || s.rule === 'ENRICHMENT_SUSPICIOUS')
        const sessionHitCount = redisHits?.filter(h =>
          h.key?.includes(`ip:${acsv.src_ip}`) || h.key?.includes(`user:${acsv.user}`)
        ).reduce((sum, h) => sum + (h.count ?? 0), 0) ?? 0
        const highVolumeAlreadyFired = signals.some(s => s.rule === 'ACS_HIGH_VOLUME_DATA_ACCESS')
        const isRecurring = (sessionHitCount >= 3 || highVolumeAlreadyFired) && !hasOtherMalicious

        const severity = isRecurring ? 'LOW' : (sensitiveResource && suspiciousUser ? 'HIGH' : 'MEDIUM')
        const confidence = isRecurring ? 35 : (sensitiveResource && suspiciousUser ? 82 : 65)
        const label = isRecurring
          ? `Recurring data access pattern: ${acsv.action} on ${acsResource ?? 'unknown'} by ${acsv.user ?? 'unknown'} (possible legitimate operation)`
          : `Suspicious data access: ${acsv.action} on ${acsResource ?? 'unknown resource'} by ${acsv.user ?? 'unknown user'}`

        signals.push({
          rule: 'ACS_SUSPICIOUS_DATA_ACCESS',
          classification: sensitiveResource && suspiciousUser ? 'Suspicious Cloud Data Access' : sensitiveResource ? 'Sensitive Resource Access' : 'Suspicious User Data Access',
          label,
          severity,
          confidence,
          weight: 3,
          evidence: [`event_type=network`, `action=${acsv.action}`, `resource=${acsResource ?? 'unknown'}`, `user=${acsv.user ?? 'unknown'}`],
          category: 'behavioral',
          source: 'acs',
          signal_layer: 'behavioral',
          mitre: 'T1530',
          independence_pair: ['action', 'resource']
        })
      }
    }

    // CLOUD SPECIFIC — IAM and data exfil patterns
    if (acsVendor === 'cloudtrail') {
      if (acsv.action?.includes('putuserpolicy') || acsv.action?.includes('attachpolicy') || acsv.action?.includes('attachuserpolicy') || acsv.action?.includes('attachrolepolicy') || acsv.action?.includes('putrolepolicy')) {
        if (acsv.event_outcome === 'success' && checkIndependencePair(acs, 'action', 'target_user')) {
          signals.push({ rule: 'ACS_CLOUD_PRIVILEGE_ESCALATION', classification: 'Cloud IAM Privilege Escalation', label: 'Cloud IAM privilege escalation — policy attached successfully', severity: 'CRITICAL', confidence: 85, weight: 5, evidence: [`action=${acsv.action}`, `user=${acsv.user ?? 'unknown'}`, `target_user=${acsv.target_user ?? 'unknown'}`, `event_outcome=success`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1098', independence_pair: ['action', 'target_user'] })
        } else if (acsv.event_outcome === 'failure' && checkIndependencePair(acs, 'action', 'event_outcome')) {
          signals.push({ rule: 'ACS_CLOUD_PRIVILEGE_ESCALATION_ATTEMPT', classification: 'Cloud IAM Privilege Escalation Attempt', label: 'Cloud IAM privilege escalation attempt — policy attachment denied', severity: 'HIGH', confidence: 72, weight: 4, evidence: [`action=${acsv.action}`, `user=${acsv.user ?? 'unknown'}`, `event_outcome=failure`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1098', independence_pair: ['action', 'event_outcome'] })
        }
      }
      if (acsv.event_outcome === 'failure' && acsv.action?.includes('assume') && checkIndependencePair(acs, 'action', 'src_ip')) {
        signals.push({ rule: 'ACS_CLOUD_ROLE_ASSUMPTION_FAIL', classification: 'Cloud Role Assumption Failure', label: 'Failed cloud role assumption attempt', severity: 'MEDIUM', confidence: 70, weight: 3, evidence: [`action=${acsv.action}`, `src_ip=${acsv.src_ip ?? 'unknown'}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1078.004', independence_pair: ['action', 'src_ip'] })
      }

      // HIGH VOLUME DATA ACCESS — repeated access to same resource within session
      // Gate: action + resource proxy independently sourced
      if (acsv.event_type === 'network' && acsResource && acsv.user) {
        const acsResourceField = acs.resource_name ?? acs.object_name ?? acs.task_name ?? acs.service_name ?? { value: null, source: null }
        const redisHitCount = redisHits?.filter(h =>
          h.key?.includes(`ip:${acsv.src_ip}`) || h.key?.includes(`user:${acsv.user}`)
        ).reduce((sum, h) => sum + (h.count ?? 0), 0) ?? 0

        if (redisHitCount >= 3 && checkIndependencePairDirect(acs.action, acsResourceField)) {
          signals.push({
            rule: 'ACS_HIGH_VOLUME_DATA_ACCESS',
            classification: 'High-Volume Cloud Data Access',
            label: `High-frequency data access: ${acsv.user} accessed ${acsResource} ${redisHitCount}× in session`,
            severity: 'HIGH',
            confidence: 75,
            weight: 3,
            evidence: [`user=${acsv.user}`, `resource=${acsResource}`, `session_count=${redisHitCount}`],
            category: 'behavioral',
            source: 'acs',
            signal_layer: 'behavioral',
            mitre: 'T1530',
            independence_pair: ['action', 'resource']
          })
        }
      }
    }

  }

  // COMMAND-LINE SIGNALS — lower normScore threshold: command_line extraction is independent of normalization
  // Gate: command_line + process_name independently sourced (command_line is raw extraction, process_name from separate field)
  if (acsv && acsv.command_line && normScore >= 0.2) {
    const cmd = acsv.command_line.toLowerCase()
    const hasCmdGate = checkIndependencePairOr(acs,
      ['command_line', 'process_name'],
      ['command_line', 'host']
    )

    if (hasCmdGate && /wget|curl.*http|bash.*-c.*http|python.*urllib|nc\s+-e|ncat|mshta.*http|certutil.*http|certutil.*-urlcache|bitsadmin.*http|regsvr32.*http|rundll32.*http|wscript.*http/i.test(cmd)) {
      signals.push({ rule: 'ACS_REMOTE_DOWNLOAD', classification: 'Remote File Download via Command Line', label: `Remote download/execution via command line (${acsVendor})`, severity: 'HIGH', confidence: 82, weight: 4, evidence: [`command_line=${acsv.command_line.slice(0, 80)}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1105', independence_pair: checkIndependencePair(acs, 'command_line', 'process_name') ? ['command_line', 'process_name'] : ['command_line', 'host'] })
    }

    if (hasCmdGate && /base64.*decode|echo.*\|.*base64|openssl.*base64|base64\s+-d/i.test(cmd)) {
      signals.push({ rule: 'ACS_BASE64_EXECUTION', classification: 'Obfuscated Command Execution', label: `Base64-encoded command execution (${acsVendor})`, severity: 'HIGH', confidence: 80, weight: 4, evidence: [`command_line=${acsv.command_line.slice(0, 80)}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1027', independence_pair: checkIndependencePair(acs, 'command_line', 'process_name') ? ['command_line', 'process_name'] : ['command_line', 'host'] })
    }

    const isSudoContext = acsVendor === 'linux' && (acsv.action === 'privilege_escalation' || acsv.action === 'command_executed')
    const shellBinary = /\/(bash|sh|python|perl|ruby|php|nc|ncat)\s*$|sudo\s+(bash|sh|python|perl|ruby|php|nc|ncat)/i.test(cmd)
    // ACS_SUDO_SHELL uses its own gate — falls back to (command_line, user)
    // when process_name is null (sudo: colon-format logs without [pid])
    const hasSudoGate = checkIndependencePairOr(acs,
      ['command_line', 'process_name'],
      ['command_line', 'user']
    )
    if (isSudoContext && shellBinary && hasSudoGate) {
      signals.push({ rule: 'ACS_SUDO_SHELL', classification: 'Privilege Abuse via Sudo Shell', label: `Sudo to interactive shell (${acsVendor})`, severity: 'CRITICAL', confidence: 90, weight: 4, evidence: [`command_line=${acsv.command_line.slice(0, 80)}`], category: 'behavioral', source: 'acs', signal_layer: 'behavioral', mitre: 'T1548.003', independence_pair: hasCmdGate ? ['command_line', 'process_name'] : ['command_line', 'user'] })
    }
  }

  // PARTIAL DETECTION — outside normScore guard, fires on generic low-confidence normalization
  // Suppressed when a strong behavioral signal (weight >= 3) already exists — avoid noise
  const hasStrongBehavioralSignal = signals.some(s => s.signal_layer === 'behavioral' && (s.weight ?? 0) >= 3)
  if (acsObject?.meta?.is_generic && normScore < 0.5 && !hasStrongBehavioralSignal) {
    signals.push({ rule: 'ACS_PARTIAL_DETECTION', classification: 'Partial Detection — Unknown Log Format', label: 'Partial normalization — limited behavioral detection', severity: 'LOW', confidence: 30, weight: 1, evidence: [`normalization_score=${normScore}`, `vendor=unknown`], category: 'enrichment', source: 'acs', signal_layer: 'enrichment', mitre: null })
  }

  return signals
}

function getMitreTactic(mitreId) {
  if (!mitreId) return null
  const map = {
    'T1110': 'Credential Access', 'T1110.001': 'Credential Access', 'T1110.003': 'Credential Access',
    'T1003': 'Credential Access', 'T1003.001': 'Credential Access', 'T1003.002': 'Credential Access', 'T1003.003': 'Credential Access',
    'T1078': 'Initial Access', 'T1566': 'Initial Access', 'T1566.001': 'Initial Access',
    'T1059': 'Execution', 'T1059.001': 'Execution', 'T1059.003': 'Execution',
    'T1204': 'Execution', 'T1204.002': 'Execution',
    'T1053': 'Persistence', 'T1053.005': 'Persistence',
    'T1543': 'Persistence', 'T1543.003': 'Persistence',
    'T1136': 'Persistence', 'T1136.001': 'Persistence',
    'T1098': 'Persistence',
    'T1055': 'Defense Evasion', 'T1070': 'Defense Evasion', 'T1070.001': 'Defense Evasion',
    'T1218': 'Defense Evasion', 'T1218.005': 'Defense Evasion', 'T1218.011': 'Defense Evasion',
    'T1027': 'Defense Evasion', 'T1027.010': 'Defense Evasion',
    'T1105': 'Command and Control',
    'T1021': 'Lateral Movement', 'T1021.002': 'Lateral Movement', 'T1021.006': 'Lateral Movement',
    'T1569': 'Execution', 'T1569.002': 'Execution',
    'T1548': 'Privilege Escalation', 'T1548.002': 'Privilege Escalation',
    'T1134': 'Privilege Escalation',
    'T1087': 'Discovery',
    'T1078.004': 'Privilege Escalation',
  }
  const base = mitreId.split('.')[0]
  return map[mitreId] ?? map[base] ?? null
}

function computeQualityFactor(normalizationScore, parseQuality, signals) {
  const hasSignalDivergence = (() => {
    const tacticGroups = signals.filter(s => s.mitre).map(s => {
      const t = s.mitre?.split('.')?.[0]
      const tacticMap = {
        'T1110': 'CredentialAccess', 'T1003': 'CredentialAccess',
        'T1059': 'Execution', 'T1204': 'Execution', 'T1569': 'Execution',
        'T1053': 'Persistence', 'T1543': 'Persistence', 'T1136': 'Persistence', 'T1098': 'Persistence',
        'T1055': 'DefenseEvasion', 'T1070': 'DefenseEvasion', 'T1218': 'DefenseEvasion', 'T1027': 'DefenseEvasion',
        'T1105': 'CommandControl',
        'T1021': 'LateralMovement',
        'T1548': 'PrivilegeEscalation', 'T1134': 'PrivilegeEscalation', 'T1078': 'PrivilegeEscalation',
        'T1087': 'Discovery',
        'T1566': 'InitialAccess',
      }
      return tacticMap[t] ?? null
    }).filter(Boolean)
    return new Set(tacticGroups).size >= 3
  })()
  // 'generic' = vendor detection failed entirely, not just partial parse
  if (parseQuality === 'generic' || parseQuality === 'unknown') return 'UNKNOWN'
  if (normalizationScore >= 0.85 && parseQuality === 'structured' && !hasSignalDivergence) return 'HIGH'
  if (normalizationScore >= 0.60 || (parseQuality === 'structured' && normalizationScore >= 0.45)) return 'MEDIUM'
  if (normalizationScore < 0.30) return 'UNKNOWN'
  return 'LOW'
}

// Applies post-aggregation verdict overrides that require
// streaming handler context (vendor origin, enrichment results)
// unavailable inside aggregateSignals.
//
// INSUFFICIENT_DATA: fires only when the engine ran successfully
// but the input was too sparse to process meaningfully.
// Distinct from NO_DETECTION (system understood input, found nothing)
// and from engine error (system failed to run).
//
// Returns a new object — does not mutate the input verdict.
function applyVerdictOverrides(verdict, { isGenericVendor, normalizationScore, hasNoIPs }) {
  if (isGenericVendor && normalizationScore <= 0.1 && hasNoIPs) {
    return {
      ...verdict,
      verdictClass:           'INSUFFICIENT_DATA',
      verdictReliabilityClass: 'TRACE_REQUIRED',
      severity:               'LOW',
      behavioral_confidence:  0,
    }
  }
  return verdict
}

function normalizeFinalVerdict(v) {
  if (!v) v = {}
  return {
    ...v,
    verdictClass:            v.verdictClass            ?? 'NO_DETECTION',
    verdictReliabilityClass: v.verdictReliabilityClass ?? 'TRACE_REQUIRED',
    severity:                v.severity                ?? 'LOW',
    classification:          v.classification          ?? 'UNKNOWN',
    confidence:              typeof v.confidence === 'number' ? v.confidence : 0,
    behavioral_confidence:   typeof v.behavioral_confidence === 'number' ? v.behavioral_confidence : 0,
    quality_factor:          v.quality_factor          ?? 'UNKNOWN',
    asset_is_critical:       v.asset_is_critical       ?? false,
    evidence:                Array.isArray(v.evidence)       ? v.evidence       : [],
    decision_trace:          Array.isArray(v.decision_trace) ? v.decision_trace : [],
    signals:                 Array.isArray(v.signals)        ? v.signals        : [],
    deterministicMitre:      v.deterministicMitre      ?? null,
  }
}

function aggregateSignals(signals, parseQuality = 'structured', normalizationScore = 0) {
  if (!signals.length) return { severity: 'LOW', classification: 'UNKNOWN', confidence: 20, asset_is_critical: false, evidence: [], decision_trace: ['No rules matched — defaulting to LOW/UNKNOWN'] }

  const severityRank   = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }
  const severityByRank = { 4: 'CRITICAL', 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW' }

  // ── Layer separation ────────────────────────────────────────────────────────
  const isBehavioral  = s => s.signal_layer === 'behavioral' || (!s.signal_layer && s.category === 'behavioral')
  const isEnrichment  = s => s.signal_layer === 'enrichment'  || (!s.signal_layer && s.category === 'enrichment')
  const isTemporal    = s => s.signal_layer === 'temporal' || s.frequency === true || s.category === 'frequency'
  const isAsset       = s => s.signal_layer === 'asset' || s.category === 'asset'
  const behavioralSignals = signals.filter(isBehavioral)
  const enrichmentSignals = signals.filter(isEnrichment)
  const temporalSignals   = signals.filter(isTemporal)
  const assetSignals      = signals.filter(isAsset)

  const sortLayer = arr => [...arr].sort((a, b) => {
    const wDiff = b.weight - a.weight
    if (wDiff !== 0) return wDiff
    return b.confidence - a.confidence
  })
  const sortedBehavioral = sortLayer(behavioralSignals)
  const sortedEnrichment = sortLayer(enrichmentSignals)
  const sortedTemporal   = sortLayer(temporalSignals)
  const sortedAsset      = sortLayer(assetSignals)

  const hasBehavioral = sortedBehavioral.length > 0

  // Frequency signals (CORRELATED_INDICATOR_ACTIVITY, REPEATED_INDICATOR) define severity context but
  // should not occupy the dominant slot — the dominant slot drives classification label.
  // Frequency signals (category === 'frequency', frequency: true) must never occupy the
  // dominant slot — dominant drives classification label and is shown in the decision trace.
  const nonFrequencyBehavioral = sortedBehavioral.filter(s => !isTemporal(s))
  // Exclude asset signals from dominant — they amplify context, they do not detect behavior
  const behavioralNonFrequency = nonFrequencyBehavioral.filter(s =>
    (s.signal_layer === 'behavioral' || s.signal_layer === 'enrichment')
    && s.category !== 'asset'
  )

  // EventID detection signals — signal_layer='enrichment', category='behavioral'
  // These live in sortedEnrichment (not sortedBehavioral) due to routing at line 781.
  // They represent domain-specific detection knowledge (WindowsEventID semantics)
  // and should rank above pure contextual enrichment (asset, reputation) in dominance.
  const detectionEnrichment = sortedEnrichment.filter(s =>
    s.category === 'behavioral'
    && !s.frequency
    && s.category !== 'asset'
  )

  // Fallback chain — priority order:
  // 1. True behavioral signals (ACS provenance-independent, vendor-agnostic)
  // 2. Any non-frequency behavioral signal (broader pool)
  // 3. EventID detection signals (domain-specific but genuine detection)
  // 4. Any enrichment signal (contextual — ASSET_CRITICAL is last resort)
  // 5. null → NO_DETECTION / ENRICHMENT_ONLY_VERDICT
  // Non-frequency temporal signals (state-change, not recurrence)
  // are eligible for dominance when no behavioral or detection
  // enrichment signals exist. Frequency/recurrence temporal signals
  // (CORRELATED_INDICATOR_ACTIVITY, REPEATED_INDICATOR) remain
  // excluded from dominance.
  const nonFrequencyTemporal = sortedTemporal.filter(s => !s.frequency)

  const dominant = behavioralNonFrequency[0]
    ?? nonFrequencyBehavioral[0]
    ?? detectionEnrichment[0]
    ?? nonFrequencyTemporal[0]
    ?? sortedEnrichment[0]
    ?? null

  // ── Severity: behavioral base, enrichment boosts max 1 level ──────────────
  const baseSeverityRank = hasBehavioral
    ? Math.max(...sortedBehavioral.map(s => severityRank[s.severity] ?? 1))
    : (dominant !== null ? (severityRank[dominant.severity] ?? 1) : 1)

  let finalSeverityRank = baseSeverityRank
  if (enrichmentSignals.length > 0) {
    const maxEnrichRank = Math.max(...enrichmentSignals.map(s => severityRank[s.severity] ?? 1))
    finalSeverityRank = Math.min(baseSeverityRank + 1, Math.max(baseSeverityRank, maxEnrichRank))
  }
  finalSeverityRank = Math.min(finalSeverityRank, 4)

  // Severity floor: confirmed malicious IP always elevates to minimum HIGH
  const hasConfirmedMalicious = signals.some(s => s.rule === 'ENRICHMENT_CONFIRMED_MALICIOUS')
  const flooredSeverityRank = hasConfirmedMalicious ? Math.max(finalSeverityRank, 3) : finalSeverityRank
  let finalSeverity = severityByRank[flooredSeverityRank] ?? 'LOW'
  let finalSeverityRankMutable = flooredSeverityRank
  const severityWasFloored = hasConfirmedMalicious && flooredSeverityRank > finalSeverityRank
  const assetIsCritical = assetSignals.some(s => ['CRITICAL','HIGH'].includes(s.severity))

  // ── Temporal severity floor ────────────────────────────────────────────────
  // Temporal signals (recurrence, cross-asset correlation) provide a minimum
  // severity floor. They do not define base severity (that belongs to behavioral
  // signals) but raise the floor when pattern recurrence or breadth warrants it.
  const hasCampaignTemporal = sortedTemporal.some(s => s.rule === 'CORRELATED_INDICATOR_ACTIVITY')
  const hasRepeatedTemporal = sortedTemporal.some(s => s.rule === 'REPEATED_INDICATOR')
  let temporalFloorEntry = null

  if (hasCampaignTemporal && finalSeverityRankMutable < (severityRank['HIGH'] ?? 3)) {
    const prevSeverity = finalSeverity
    finalSeverity = 'HIGH'
    finalSeverityRankMutable = severityRank['HIGH'] ?? 3
    temporalFloorEntry = { type: 'floor', label: 'Severity elevated to HIGH minimum — correlated indicator activity across multiple assets', rule: 'CORRELATED_INDICATOR_ACTIVITY', from: prevSeverity, to: 'HIGH' }
  } else if (hasRepeatedTemporal && finalSeverityRankMutable < (severityRank['MEDIUM'] ?? 2)) {
    const prevSeverity = finalSeverity
    finalSeverity = 'MEDIUM'
    finalSeverityRankMutable = severityRank['MEDIUM'] ?? 2
    temporalFloorEntry = { type: 'floor', label: 'Severity elevated to MEDIUM minimum — repeated indicator in session', rule: 'REPEATED_INDICATOR', from: prevSeverity, to: 'MEDIUM' }
  }

  // State-change temporal signals at CRITICAL can set CRITICAL floor
  const hasCriticalTemporalSignal = sortedTemporal.some(
    s => !s.frequency && s.severity === 'CRITICAL'
  )

  if (hasCriticalTemporalSignal && finalSeverityRankMutable < (severityRank['CRITICAL'] ?? 4)) {
    const prevSeverity = finalSeverity
    finalSeverity = 'CRITICAL'
    finalSeverityRankMutable = severityRank['CRITICAL'] ?? 4
    temporalFloorEntry = {
      type: 'floor',
      label: 'Severity elevated to CRITICAL — state-change temporal signal present',
      rule: sortedTemporal.find(s => !s.frequency && s.severity === 'CRITICAL')?.rule,
      from: prevSeverity,
      to: 'CRITICAL',
    }
  }

  const classificationMap = {
    BRUTE_FORCE_EXTREME: 'Brute Force Attack', BRUTE_FORCE_HIGH: 'Brute Force Attack',
    BRUTE_FORCE_MEDIUM: 'Password Spraying', LOGON_FAILURE_LOW: 'Failed Logon',
    LOLBIN_CERTUTIL_DOWNLOAD: 'Malicious File Download via LOLBin',
    LOLBIN_CERTUTIL_SUSPICIOUS_PATH: 'LOLBin Staging to Suspicious Path',
    LOLBIN_MSHTA_REMOTE: 'Remote Script Execution via mshta',
    OFFICE_MACRO_DROPPER: 'Macro-based Dropper Execution',
    BROWSER_SPAWN_SCRIPTING: 'Browser Process Spawning Scripting Host',
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
    CORRELATED_INDICATOR_ACTIVITY: 'Multi-Asset Coordinated Attack',
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
    ACS_CLOUD_PRIVILEGE_ESCALATION:         'Cloud IAM Privilege Escalation',
    ACS_CLOUD_PRIVILEGE_ESCALATION_ATTEMPT: 'Cloud IAM Privilege Escalation Attempt',
    ACS_CLOUD_ROLE_ASSUMPTION_FAIL:         'Cloud Role Assumption Failure',
    ACS_SUSPICIOUS_DATA_ACCESS:        'Suspicious Cloud Data Access',
    ACS_OBJECT_ACCESS_SENSITIVE:       'Credential Resource Access',
    ACS_LATERAL_MOVEMENT_CANDIDATE:   'Lateral Movement Candidate',
    ACS_HIGH_VOLUME_DATA_ACCESS:       'High-Volume Cloud Data Access',
    ACS_ACCOUNT_DELETION:              'Account Deletion — Potential Evidence Destruction',
    ACS_PARTIAL_DETECTION:             'Partial Detection — Unknown Log Format',
    ACS_MALICIOUS_SOURCE_AUTH_SUCCESS: 'Successful Authentication from Malicious Source',
  }

  // Classification comes ONLY from behavioral signals — frequency signals cannot drive classification.
  const eventBehavioral = sortedBehavioral.find(s => s.category === 'behavioral')
  const topEnrichment = sortedEnrichment.find(s => s.category !== 'asset' && s.category !== 'frequency')

  const genericAcsRules = ['ACS_PRIVILEGE_ACTION', 'ACS_PARTIAL_DETECTION']
  const eventBehavioralIsGeneric = eventBehavioral && genericAcsRules.includes(eventBehavioral.rule)

  // When the event behavioral signal is a generic catch-all AND a specific enrichment signal
  // has its own classification, prefer the enrichment classification.
  // This prevents "Privilege Escalation Detected" from overriding "Security Log Tampering".
  const specificEnrichment = sortedEnrichment.find(s =>
    s.classification &&
    s.category !== 'asset' &&
    s.rule !== 'ENRICHMENT_CONFIRMED_MALICIOUS' &&
    s.rule !== 'ENRICHMENT_SUSPICIOUS' &&
    s.rule !== 'ENRICHMENT_CLEAN'
  )

  // Non-frequency temporal signals with classificationMap entries are eligible as
  // classification sources — they represent genuine state-change detections.
  // Priority: behavioral > temporal > enrichment > dominant.
  const temporalClassificationSource = sortedTemporal
    .filter(s => !s.frequency && classificationMap[s.rule])
    .sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0))[0] ?? null

  const classificationSource = (eventBehavioralIsGeneric && specificEnrichment)
    ? specificEnrichment
    : eventBehavioral ?? temporalClassificationSource ?? topEnrichment ?? dominant

  const classificationReason = (eventBehavioralIsGeneric && specificEnrichment)
    ? 'enrichment_specific'
    : eventBehavioral ? 'event_behavioral'
    : temporalClassificationSource ? 'temporal'
    : topEnrichment ? 'enrichment'
    : 'dominant'

  const classification = classificationSource?.classification ?? classificationMap[classificationSource?.rule] ?? 'UNKNOWN'
  // If classification source is a generic ACS catch-all, prefer the most specific enrichment MITRE
  const classificationIsGeneric = genericAcsRules.includes(classificationSource?.rule)
  const specificEnrichmentMitre = sortedEnrichment.find(s => s.mitre && s.rule !== 'ENRICHMENT_CONFIRMED_MALICIOUS' && s.rule !== 'ENRICHMENT_SUSPICIOUS' && s.rule !== 'ENRICHMENT_CLEAN')?.mitre

  const deterministicMitre = (!classificationIsGeneric ? classificationSource?.mitre : null)
    ?? specificEnrichmentMitre
    ?? sortedBehavioral.find(s => s.mitre)?.mitre
    ?? sortedTemporal.filter(s => !s.frequency).find(s => s.mitre)?.mitre
    ?? sortedEnrichment.find(s => s.mitre)?.mitre
    ?? null

  // ── Model E: behavioral_confidence ────────────────────────────────────────
  const dominantConf = dominant?.confidence ?? 0
  // Filter by identity against dominant — not slice(1) — because dominant is selected
  // from behavioralNonFrequency (a filtered subset of sortedBehavioral) and may not
  // occupy index 0. slice(1) double-counts the dominant if any higher-ranked signal
  // is excluded from dominance by the temporal or asset filters.
  const behavioralSupporters = sortedBehavioral.filter(s =>
    s !== dominant
    && !isTemporal(s) && s.category !== 'asset'
    && (s.signal_layer === 'behavioral' || s.category === 'behavioral'))
  const supportingContrib = behavioralSupporters
    .reduce((acc, s, i) => acc + (s.confidence * (0.25 / (i + 2))), 0)
  const temporalBoost = sortedTemporal.length > 0
    ? Math.min(10, sortedTemporal[0].confidence * 0.12) : 0
  const hasEnrichmentAlignment = signals.some(s =>
    s.rule === 'ENRICHMENT_CONFIRMED_MALICIOUS' || s.rule === 'ENRICHMENT_SUSPICIOUS')
    && (dominant?.severity === 'CRITICAL' || dominant?.severity === 'HIGH')
  const enrichmentAlignment = hasEnrichmentAlignment ? 5 : 0
  const behavioral_confidence = Math.round(Math.min(100,
    dominantConf + supportingContrib + temporalBoost + enrichmentAlignment))

  const quality_factor = computeQualityFactor(normalizationScore, parseQuality, signals)

  // Legacy confidence — kept for narrator prompt compatibility
  const finalConfidence = behavioral_confidence

  // ── Layer summary ──────────────────────────────────────────────────────────
  const layer_summary = {
    behavioral:      sortedBehavioral.length,
    enrichment:      enrichmentSignals.length,
    temporal:        sortedTemporal.length,
    asset:           assetSignals.length,
    dominant_layer:  dominant?.signal_layer ?? (hasBehavioral ? 'behavioral' : 'enrichment'),
    severity_boosted: finalSeverityRank > baseSeverityRank,
  }

  const decision_trace = [
    ...(dominant !== null ? [{ type: 'dominant', label: dominant.label, category: dominant.category, weight: dominant.weight, confidence: dominant.confidence, rule: dominant.rule }] : [{ type: 'dominant', label: 'No non-frequency behavioral signals', category: null, weight: 0, confidence: 0, rule: null }]),
    { type: 'severity',      label: `${finalSeverity} across ${signals.length} signals`, value: finalSeverity },
    ...(severityWasFloored ? [{ type: 'floor', label: `Severity elevated to HIGH minimum — confirmed malicious IP present`, rule: 'ENRICHMENT_CONFIRMED_MALICIOUS', from: severityByRank[finalSeverityRank], to: finalSeverity }] : []),
    { type: 'classification', label: classification, rule: classificationSource?.rule, layer: classificationSource?.signal_layer, reason: classificationReason },
    { type: 'asset',         label: `Critical: ${assetIsCritical}`, value: assetIsCritical },
    ...(temporalFloorEntry ? [temporalFloorEntry] : []),
    { type: 'confidence',    label: `${behavioral_confidence}`, dominantConf, supportingContrib: Math.round(supportingContrib), temporalBoost: Math.round(temporalBoost), enrichmentAlignment, quality_factor },
    { type: 'layer_summary', label: `behavioral=${layer_summary.behavioral} enrichment=${layer_summary.enrichment} temporal=${layer_summary.temporal} dominant=${layer_summary.dominant_layer}${layer_summary.severity_boosted ? ' [severity boosted]' : ''}`, ...layer_summary },
    ...[...sortedBehavioral.slice(1), ...sortedEnrichment].map(s => ({ type: 'supporting', label: s.label, severity: s.severity, category: s.category, rule: s.rule, signal_layer: s.signal_layer }))
  ]

  // ── Verdict reliability classification ──────────────────────────────────────
  const hasBehavioralForVerdict = signals.some(s =>
    s.signal_layer === 'behavioral' && !isTemporal(s))

  const hasDetectionEnrichment = signals.some(s =>
    s.signal_layer === 'enrichment' && s.category === 'behavioral')

  const hasNonFrequencyTemporal = (sortedTemporal ?? []).some(
    s => !s.frequency && s.category !== 'frequency'
  )

  const verdictClass = (() => {
    if (!hasBehavioralForVerdict && !hasDetectionEnrichment && !hasNonFrequencyTemporal)
      return 'NO_DETECTION'
    if (!hasBehavioralForVerdict && !hasDetectionEnrichment && hasNonFrequencyTemporal)
      return 'DEFENSIBLE_VERDICT'
    if (!hasBehavioralForVerdict && hasDetectionEnrichment)
      return 'ENRICHMENT_ONLY_VERDICT'
    if (normalizationScore < 0.3 || (dominant?.weight ?? 0) < 2)
      return 'LOW_CONFIDENCE_VERDICT'
    return 'DEFENSIBLE_VERDICT'
  })()

  // ENRICHMENT_ONLY_VERDICT is always TRACE_REQUIRED — never surface safe
  // without vendor-agnostic behavioral evidence.
  // Temporal-only verdicts always require trace validation — session context
  // must be understood before acting on a temporal-only classification.
  const verdictReliabilityClass = (() => {
    if (verdictClass !== 'DEFENSIBLE_VERDICT') return 'TRACE_REQUIRED'
    if (!hasBehavioralForVerdict && !hasDetectionEnrichment && hasNonFrequencyTemporal)
      return 'TRACE_REQUIRED'
    const dominantWeight = dominant?.weight ?? 0
    const hasSignalContradiction = (() => {
      const tactics = [...new Set(signals
        .filter(s => s.mitre)
        .map(s => getMitreTactic(s.mitre))
        .filter(Boolean))]
      return tactics.length >= 3
    })()
    if (dominantWeight >= 4 && normalizationScore >= 0.7 && !hasSignalContradiction)
      return 'SURFACE_SAFE'
    return 'TRACE_REQUIRED'
  })()

  return {
    severity:                  finalSeverity,
    classification,
    confidence:                behavioral_confidence,
    behavioral_confidence,
    quality_factor,
    asset_is_critical:         assetIsCritical,
    affected_asset:            null,
    evidence:                  [...new Set((signals ?? []).flatMap(s => s.evidence ?? []))].slice(0, 8),
    decision_trace:            decision_trace ?? [],
    signals:                   signals ?? [],
    deterministicMitre,
    verdictClass,
    verdictReliabilityClass,
  }
}

// ── DETERMINISTIC RECOMMENDATIONS ────────────────────────────────────────────
// Static per-rule recommendation banks. buildDeterministicRecommendations selects
// up to 5 unique entries from fired behavioral signals ordered by weight descending.
// Tokens: {host} {user} {src_ip} — filled at call time from acsObject / triage data.

const RECOMMENDATION_LOOKUP = {
  ACS_AUTH_FAILURE_LOW: [
    "Verify whether the authentication failure was isolated or part of a broader pattern",
    "Check if the account targeted has been accessed successfully from the same source recently",
  ],
  ACS_AUTH_FAILURE_HIGH: [
    "Verify whether any successful authentication followed the failure sequence",
    "Check if the targeted account shows signs of lockout or policy modification",
    "Correlate the failure source with known infrastructure or previous session activity",
  ],
  ACS_AUTH_FAILURE_MASS: [
    "Verify whether any authentication succeeded during or after the failure window",
    "Correlate the source IP with other activity in the session",
    "Check whether the volume pattern suggests automated tooling or manual activity",
  ],
  ACS_PRIVILEGE_ACTION: [
    "Verify whether the privilege action was authorized and expected for this account",
    "Check whether the action was preceded by unusual authentication or access patterns",
    "Correlate with other privilege-related events on the same asset",
  ],
  ACS_CLOUD_PRIVILEGE_ESCALATION: [
    "Verify whether the policy attachment was authorized and matches expected IAM activity",
    "Check the current effective permissions of the target account after the action",
    "Correlate with other IAM changes in the same time window",
  ],
  ACS_CLOUD_PRIVILEGE_ESCALATION_ATTEMPT: [
    "Verify whether the blocked policy attachment represents a persistent adversary probing IAM permissions",
    "Check whether other IAM operations were attempted from the same source before or after this event",
    "Correlate the source IP with other AWS API activity in the session to assess scope of probing",
  ],
  ACS_CLOUD_ROLE_ASSUMPTION_FAIL: [
    "Verify whether the role assumption attempt was expected for this identity",
    "Check whether the failure was followed by a successful assumption from another path",
    "Correlate the source with other AWS API activity in the session",
  ],
  ACS_REMOTE_DOWNLOAD: [
    "Verify whether the remote resource accessed is known infrastructure or unexpected",
    "Check whether any files were written to disk following the download attempt",
    "Correlate the destination with other network connections from the affected host",
  ],
  ACS_BASE64_EXECUTION: [
    "Verify whether the encoding pattern matches known legitimate automation on this host",
    "Check for any child processes or file writes following the encoded execution",
    "Correlate with other command execution events on the same asset",
  ],
  ACS_SUDO_SHELL: [
    "Verify whether the interactive shell escalation was authorized for this account",
    "Check for commands executed within the escalated shell session",
    "Correlate with other privilege events on the same host",
  ],
  ACS_SUSPICIOUS_DATA_ACCESS: [
    "Verify whether the resource accessed is within the expected scope for this account",
    "Check whether the access volume or pattern differs from baseline behavior",
    "Correlate with other access events on the same resource in the session",
  ],
  ACS_OBJECT_ACCESS_SENSITIVE: [
    "Verify whether access to this resource was expected for the acting identity",
    "Check whether the access was read-only or included write or delete operations",
  ],
  ACS_LATERAL_MOVEMENT_CANDIDATE: [
    "Verify whether the source and destination hosts share an expected trust relationship",
    "Check whether the credential used is consistent with normal access patterns",
    "Correlate with authentication events on the destination host",
  ],
  ACS_HIGH_VOLUME_DATA_ACCESS: [
    "Verify whether the access volume is consistent with legitimate activity for this account",
    "Check whether the data accessed was exfiltrated or remained within the environment",
  ],
  ACS_ACCOUNT_DELETION: [
    "Verify whether the account deletion was authorized and matches expected lifecycle activity",
    "Check whether the deleted account had active sessions or elevated permissions",
  ],
  ACS_PARTIAL_DETECTION: [
    "Verify whether a more specific parser applies to this log format",
    "Correlate any extracted indicators with other session activity before drawing conclusions",
  ],
  ACS_MALICIOUS_SOURCE_AUTH_SUCCESS: [
    "Verify whether the successful authentication represents a legitimate access or a compromised credential",
    "Check all actions taken by this identity after the successful authentication in this session",
    "Correlate this authentication with the prior failure sequence from the same source to assess attack progression",
  ],
  BRUTE_FORCE_EXTREME: [
    "Verify whether any authentication succeeded following the brute force sequence",
    "Check whether account lockout policies functioned as expected during the attack",
    "Correlate the source with known threat infrastructure or previous session activity",
  ],
  BRUTE_FORCE_HIGH: [
    "Verify whether the failure pattern is consistent with credential stuffing or targeted guessing",
    "Check whether the targeted account shows signs of compromise following the failures",
  ],
  BRUTE_FORCE_MEDIUM: [
    "Verify whether the failure count represents automated tooling or manual attempts",
    "Check whether the source IP has appeared in other authentication events",
  ],
  LOGON_FAILURE_LOW: [
    "Verify whether the failure was isolated or the beginning of a broader pattern",
    "Check whether the account targeted is active and the credential configuration is valid",
  ],
  LOLBIN_CERTUTIL_DOWNLOAD: [
    "Verify whether certutil was invoked for a legitimate certificate operation or as a download proxy",
    "Check whether any files were written to disk as a result of the certutil execution",
    "Correlate with other process execution events on the affected host",
  ],
  LOLBIN_CERTUTIL_SUSPICIOUS_PATH: [
    "Verify whether the file written to the suspicious path was subsequently executed",
    "Check the file written for indicators of staged payloads or known malicious content",
  ],
  LOLBIN_MSHTA_REMOTE: [
    "Verify whether the remote resource contacted by mshta is known or expected infrastructure",
    "Check whether mshta spawned any child processes following the remote connection",
  ],
  OFFICE_MACRO_DROPPER: [
    "Verify whether the Office document that triggered the child process was expected or externally received",
    "Check whether the spawned process made any network connections or file writes",
    "Correlate with document delivery or sharing events preceding the execution",
  ],
  POWERSHELL_ENCODED: [
    "Verify whether encoded PowerShell execution is expected or authorized in this environment",
    "Check for any network connections or file operations following the execution",
    "Correlate with other command execution events on the affected host",
  ],
  SCHEDULED_TASK_CRADLE: [
    "Verify whether the scheduled task was created by an authorized process or account",
    "Check the task action content for indicators of download cradle or execution chain",
    "Correlate with other persistence or execution events on the same asset",
  ],
  SCHEDULED_TASK_CREATED: [
    "Verify whether the scheduled task creation was authorized and expected",
    "Check the task trigger, action, and author against known legitimate configurations",
  ],
  SERVICE_SUSPICIOUS_PATH: [
    "Verify whether the service binary path resolves to a legitimate executable",
    "Check the service creation context — which account created it and when",
  ],
  AUDIT_LOG_CLEARED: [
    "Verify whether the log clearing was authorized and part of a known maintenance procedure",
    "Check for activity immediately preceding the clearing that may have been intentionally removed",
    "Correlate with other defense evasion indicators on the same host",
  ],
  ACCOUNT_CREATED_SUSPICIOUS: [
    "Verify whether the new account name matches any legitimate provisioning patterns",
    "Check whether the account was added to any groups or granted permissions after creation",
    "Correlate account creation with other activity from the creating principal",
  ],
  ACCOUNT_CREATED: [
    "Verify whether the account creation was expected and follows normal provisioning procedure",
    "Check whether the creating account had authorization for user management",
  ],
  NTDS_ACCESS: [
    "Verify whether access to the NTDS database was expected for this account and process",
    "Check whether any credential extraction indicators are present on the host",
    "Correlate with other credential access events in the session",
  ],
  SAM_ACCESS: [
    "Verify whether access to the SAM database was expected for this account and process",
    "Check whether the access pattern is consistent with known credential extraction techniques",
  ],
  LSASS_DUMP_RUNDLL32: [
    "Verify whether the comsvcs MiniDump invocation was expected or authorized on this host",
    "Check whether any dump files were written to disk and whether they persist",
    "Correlate with other credential access or lateral movement indicators",
  ],
  MIMIKATZ_DETECTED: [
    "Verify whether the process invoking credential access patterns was expected on this host",
    "Check for any subsequent lateral movement or new authentication events",
    "Correlate with other persistence or execution indicators in the session",
  ],
  ASSET_CRITICAL: [
    "Verify whether access to this critical asset was expected from the observed source",
    "Check all other indicators with elevated scrutiny given the asset criticality",
  ],
}

function buildDeterministicRecommendations(signals, affectedAsset, acsObject) {
  const host     = affectedAsset ?? 'AFFECTED_HOST'
  const user     = acsObject?.acs_data?.user?.value ?? 'AFFECTED_USER'
  const srcIp    = acsObject?.acs_data?.src_ip?.value ?? 'UNKNOWN_IP'
  const resource = (acsObject?.acs_data?.object_name?.value ?? acsObject?.acs_data?.task_name?.value ?? acsObject?.acs_data?.service_name?.value ?? acsObject?.acs_data?.resource_name?.value ?? 'UNKNOWN_RESOURCE')

  const fill = (s) => s
    .replace(/{host}/g, host)
    .replace(/{user}/g, user)
    .replace(/{src_ip}/g, srcIp)
    .replace(/{resource}/g, resource)

  const contributing = [...(signals ?? [])]
    .filter(s => {
      if (s.frequency === true) return false
      if (s.category === 'asset') return false
      if (s.category === 'enrichment') return false
      if (s.signal_layer === 'behavioral') return true
      // EventID-based detection signals (signal_layer=enrichment, category=behavioral)
      // are included so they can generate recommendations in ENRICHMENT_ONLY_VERDICT
      if (s.signal_layer === 'enrichment' && s.category === 'behavioral') return true
      // Non-frequency temporal signals with lookup entries contribute
      if (s.signal_layer === 'temporal' && !s.frequency && RECOMMENDATION_LOOKUP[s.rule]) return true
      return false
    })
    .sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0))

  if (contributing.length === 0) return { recommendations: [], provenance: [] }

  const recommendations = []
  const provenance = []
  const seen = new Set()

  for (const signal of contributing) {
    const entries = RECOMMENDATION_LOOKUP[signal.rule] ?? []
    for (const entry of entries) {
      const filled = fill(entry)
      if (!seen.has(filled) && recommendations.length < 5) {
        seen.add(filled)
        recommendations.push(filled)
        provenance.push(signal.rule)
      }
    }
    if (recommendations.length >= 5) break
  }

  return { recommendations: recommendations.slice(0, 5), provenance: provenance.slice(0, 5) }
}

function buildNarratorPrompt(sanitizedAlert, parsedContext, enrichmentJudgment, redisContext, isActiveCampaign, uniqueAssetCount, frequencyMultiplier, finalVerdict, acsObject = null) {
  return `You are ARBITER's Narrator Layer. A deterministic engine has already classified this alert — your role is synthesis only.

YOUR ROLE IS STRICTLY LIMITED TO:
1. Writing one synthesis paragraph explaining the behavior and its significance
2. Identifying the MITRE ATT&CK tactic and tactic name
3. Populating the indicators field with technical facts extracted from the alert

YOU MUST NOT produce: recommendations, mitre_id, mitre_name, severity overrides, or confidence overrides.

═══ FINAL VERDICT (DETERMINISTIC — DO NOT OVERRIDE) ═══
severity: ${finalVerdict.severity}
classification: ${finalVerdict.classification}
behavioral_confidence: ${finalVerdict.behavioral_confidence}
quality_factor: ${finalVerdict.quality_factor}
verdict_class: ${finalVerdict.verdictClass}
asset_is_critical: ${finalVerdict.asset_is_critical}
decision_trace: ${finalVerdict.decision_trace.slice(0,3).map(d => typeof d === 'object' ? d.label : d).join(' | ')}

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

${redisContext ? `TEMPORAL CORRELATION:\n${redisContext}\n${isActiveCampaign ? `ACTIVE CAMPAIGN: ${frequencyMultiplier} hits across ${uniqueAssetCount} unique assets.` : ''}` : ''}

Return ONLY a JSON object. No markdown, no backticks, no preamble:
{
  "indicators": string[] (3-8 technical facts from the alert — EventCodes, binary names, arguments, asset names, timestamps),
  "tactic": string (MITRE tactic name — e.g. "Credential Access", "Defense Evasion", "Execution"),
  "mitre_tactic": string (must match tactic exactly),
  "reasoning": string (one synthesis paragraph as a plain string — synthesize what the behavioral signals mean together, what the enrichment context adds, and the overall risk picture for this alert)
}

RULES:
- reasoning MUST be a plain string — never an object or array
- DO NOT include mitre_id, mitre_name, recommendations, or recommendation_provenance
- reasoning synthesizes the full picture — do not repeat the classification verbatim`
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
      `https://otx.alienvault.com/api/v1/indicators/${ip.includes(':') ? 'IPv6' : 'IPv4'}/${ip}/general`,
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
    'T1531':     'Account Access Removal',
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
    'Account Deletion — Potential Evidence Destruction': { id: 'T1531', tactic: 'Impact' },
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
          try {
            const enrichResults = await Promise.all(ips.map(ip => enrichIP(ip)))
            ips.forEach((ip, i) => { enrichment[ip] = enrichResults[i] })
          } catch (enrichErr) {
            console.error('[ARBITER] Enrichment failed, continuing without:', enrichErr.message)
            // enrichment remains empty — enrichmentJudgment will show no verdict
          }
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
        const normalizedUsername = acsObject?.acs_data?.user?.value ?? parsedAlert.username
        const correlationUsername = normalizeUsernameForCorrelation(acsObject?.acs_data?.user?.value ?? parsedAlert.username)


        let redisContextResult = null
        try {
          redisContextResult = await getRedisContext(ips, correlationUsername, safeSessionId)
        } catch (redisErr) {
          console.error('[ARBITER] Redis read failed, continuing without correlation:', redisErr.message)
          // redisContextResult remains null — no correlation signals will fire
        }
        const redisHits    = redisContextResult?.hits ?? null
        const redisPatterns = redisContextResult?.patterns ?? []
        const redisContext = buildRedisContextSummary(redisHits)

        // Filter redisContext to only include indicators present in the current alert
        // Prevents session history from contaminating current alert recommendations
        const currentAlertIPs = new Set(ips)
        const currentAlertUsers = new Set([correlationUsername, acsObject?.acs_data?.user?.value ?? parsedAlert.username].filter(Boolean))

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
        const enrichmentJudgment  = buildEnrichmentJudgment(enrichment, ips, frequencyMultiplier)

        // Override parseQuality to 'generic' when vendor detection failed.
        // parseAlert() cannot know the vendor — normalize() detects it.
        // Must run before aggregateSignals() so computeQualityFactor() sees the correct value.
        const isGenericVendor = (acsObject?.meta?.vendor_origin ?? 'unknown') === 'unknown'
        if (isGenericVendor && parsedAlert.parseQuality !== 'structured') {
          parsedAlert.parseQuality = 'generic'
        }

        // Read internal failure history for ACS lateral movement detection.
        // extractIPs strips RFC1918 addresses — internal src_ip values are
        // excluded from the enrichment Redis namespace and need a separate
        // read path. This enables ACS_LATERAL_MOVEMENT_CANDIDATE to detect
        // cross-host auth patterns between internal hosts.
        const acsSrcIpRaw = acsObject?.acs_data?.src_ip?.value
        const isInternalSrcIpForLateral = acsSrcIpRaw
          && /^10\.|^172\.(1[6-9]|2\d|3[01])\.|^192\.168\./i.test(acsSrcIpRaw)
        let internalFailureHits = null
        if (isInternalSrcIpForLateral) {
          try {
            const internalReadKey =
              `session:${safeSessionId}:internal_failure:${acsSrcIpRaw}`
            const raw = await redis.get(internalReadKey)
            internalFailureHits = raw ?? null
          } catch {
            // Redis unavailable — fail open, lateral movement precondition
            // will treat count as 0 and suppress the signal conservatively
          }
        }

        const signals      = getSignals(parsedAlert, enrichmentJudgment, redisHits, acsObject, internalFailureHits)
        let finalVerdict
        let engineErrored = false
        try {
          finalVerdict = normalizeFinalVerdict(
            aggregateSignals(signals, parsedAlert.parseQuality,
              acsObject?.meta?.normalization_score ?? 0)
          )
        } catch (engineErr) {
          engineErrored = true
          console.error('[ARBITER] Decision engine failed:', engineErr?.message, engineErr?.stack)
          finalVerdict = normalizeFinalVerdict({
            severity: 'UNKNOWN',
            classification: 'UNKNOWN',
            confidence: 0,
            asset_is_critical: false,
            affected_asset: null,
            evidence: [],
            decision_trace: [{ type: 'error', label: 'Decision engine failed — manual review required' }],
            signals: [],
            deterministicMitre: null,
          })
        }
        if (!engineErrored) {
          finalVerdict = applyVerdictOverrides(finalVerdict, {
            isGenericVendor,
            normalizationScore: acsObject?.meta?.normalization_score ?? 0,
            hasNoIPs: ips.length === 0,
          })
        }

        const isActiveCampaign = (finalVerdict?.signals ?? signals).some(
          s => s.rule === 'CORRELATED_INDICATOR_ACTIVITY'
        )

        const parsedContext = Object.entries(parsedAlert)
          .filter(([_, v]) => v !== null)
          .map(([k, v]) => `${k}: ${v}`)
          .join('\n')

        // Narrator is suppressed for states where LLM synthesis adds no value:
        // NO_DETECTION has no signals to reason about; INSUFFICIENT_DATA has
        // insufficient provenance for a reliable narrative.
        const skipNarrator = finalVerdict.verdictClass === 'NO_DETECTION'
          || finalVerdict.verdictClass === 'INSUFFICIENT_DATA'

        const narratorFallback = (() => {
          const mitreToTactic = {
            'T1110.001': 'Credential Access', 'T1110': 'Credential Access',
            'T1105': 'Command and Control', 'T1218.005': 'Defense Evasion',
            'T1204.002': 'Execution', 'T1059.001': 'Execution',
            'T1053.005': 'Persistence', 'T1543.003': 'Persistence',
            'T1070.001': 'Defense Evasion', 'T1003.003': 'Credential Access',
            'T1003.002': 'Credential Access', 'T1078': 'Initial Access',
            'T1566.001': 'Initial Access',
          }
          const tactic = mitreToTactic[finalVerdict.deterministicMitre] ?? getMitreTactic(finalVerdict.deterministicMitre) ?? 'Unknown'
          const dominantLabel = typeof finalVerdict.decision_trace[0] === 'object' ? finalVerdict.decision_trace[0].label : (finalVerdict.decision_trace[0] ?? '')
          const asset = acsObject?.acs_data?.host?.value ?? parsedAlert.asset ?? 'the affected asset'
          const behavioralCount = (finalVerdict.signals ?? []).filter(s => s.signal_layer === 'behavioral').length
          const temporalNote = (finalVerdict.signals ?? []).some(s => s.signal_layer === 'temporal')
            ? ` Temporal correlation indicates this indicator has been observed across multiple sessions.` : ''
          return {
            indicators:   finalVerdict.decision_trace.slice(0, 5).map(d => typeof d === 'object' ? d.label : d),
            tactic,
            mitre_tactic: tactic,
            mitre_id:     finalVerdict.deterministicMitre ?? 'T0000',
            mitre_name:   finalVerdict.deterministicMitre
              ? getMitreName(finalVerdict.deterministicMitre)
              : finalVerdict.classification ?? 'Unknown',
            reasoning: skipNarrator ? null : `The deterministic engine classified this alert as ${finalVerdict.classification} (${finalVerdict.severity}) based on ${behavioralCount} behavioral signal${behavioralCount !== 1 ? 's' : ''}. ${dominantLabel}.${temporalNote} Investigate ${asset} for signs of persistence or lateral movement consistent with this classification.`,
          }
        })()

        function isValidNarratorOutput(obj) {
          if (!obj || typeof obj !== 'object') return false
          if (typeof obj.reasoning !== 'string' || obj.reasoning.trim().length < 20) return false
          if (typeof obj.tactic !== 'string' || obj.tactic.trim().length === 0) return false
          if (typeof obj.mitre_tactic !== 'string' || obj.mitre_tactic.trim().length === 0) return false
          return true
        }

        let narrator = narratorFallback
        if (!skipNarrator) {
          try {
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
            narrator = isValidNarratorOutput(narratorOutput) ? narratorOutput : narratorFallback
          } catch (groqErr) {
            console.error('[ARBITER] Groq call failed, using deterministic fallback:', groqErr.message)
            narrator = narratorFallback
          }
        }

        const { recommendations: deterministicRecommendations, provenance: deterministicProvenance }
          = buildDeterministicRecommendations(finalVerdict.signals ?? signals, null, acsObject)

        const triage = {
          severity:          finalVerdict.severity,
          classification:    finalVerdict.classification,
          confidence:        finalVerdict.confidence,
          asset_is_critical: finalVerdict.asset_is_critical,
          evidence:          finalVerdict.evidence,
          affected_asset:    (() => {
            // Priority 1: ACS normalizer host (most reliable cross-vendor), then parser asset
            const acsHostPrimary = acsObject?.acs_data?.host?.value ?? null
            if (acsHostPrimary && acsHostPrimary !== 'UNKNOWN' && acsHostPrimary.length > 0) return acsHostPrimary
            if (parsedAlert.asset && parsedAlert.asset !== 'UNKNOWN') return parsedAlert.asset
            if (parsedAlert.allAssets) {
              const first = parsedAlert.allAssets.split(',')[0]?.trim()
              if (first && first !== 'UNKNOWN') return first
            }
            // Priority 2: CloudTrail target user
            const acsTargetUser = acsObject?.acs_data?.target_user?.value ?? null
            if (acsTargetUser && acsTargetUser.length > 0) return `IAM:${acsTargetUser}`
            // Priority 2.5: ACS resource name (S3 bucket, DynamoDB table, CloudTrail resource).
            // Explicit ACS field preferred over regex scan of raw text.
            const acsResource = acsObject?.acs_data?.resource_name?.value
              ?? acsObject?.acs_data?.object_name?.value
              ?? null
            if (acsResource && acsResource !== 'UNKNOWN' && acsResource.length > 0
                && !acsResource.includes(':') && !acsResource.includes('/')) {
              return acsResource
            }
            // Priority 3: regex scan of raw alert text for computer/hostname patterns
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
            // Priority 4: use username as host identifier
            const usernameForHost = acsObject?.acs_data?.user?.value ?? parsedAlert.username
            if (usernameForHost && usernameForHost !== 'system' && !usernameForHost.includes('$') && usernameForHost.length > 3) {
              // Exclude ARN strings — they contain colons and slashes and are not meaningful asset identifiers
              if (usernameForHost.includes(':') || usernameForHost.includes('/')) {
                return 'UNKNOWN'
              }
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
            return filtered.length > 0 ? filtered : (parsedAlert.allEventCodes ? [`EventCode=${parsedAlert.allEventCodes}`, `Asset=${acsObject?.acs_data?.host?.value ?? parsedAlert.asset ?? 'UNKNOWN'}`, `User=${acsObject?.acs_data?.user?.value ?? parsedAlert.username ?? 'UNKNOWN'}`] : raw)
          })(),
          mitre_id: (() => {
            if (finalVerdict.deterministicMitre) return finalVerdict.deterministicMitre
            const classificationMitre = getClassificationMitre(finalVerdict.classification)?.id
            return classificationMitre ?? null
          })(),
          mitre_name: (() => {
            if (finalVerdict.deterministicMitre) return getMitreName(finalVerdict.deterministicMitre)
            const fb = getClassificationMitre(finalVerdict.classification)
            if (fb) return getMitreName(fb.id) ?? finalVerdict.classification
            return finalVerdict.classification
          })(),
          tactic: narrator?.tactic
               ?? narratorFallback.tactic
               ?? 'Unknown',
          mitre_tactic: getMitreTactic(finalVerdict.deterministicMitre)
                     ?? narrator?.tactic
                     ?? narratorFallback.tactic
                     ?? 'Unknown',
          recommendations:           deterministicRecommendations,
          recommendation_provenance: deterministicProvenance,
          verdict_class:             finalVerdict.verdictClass,
          verdict_reliability_class: finalVerdict.verdictReliabilityClass,
          behavioral_confidence:     finalVerdict.behavioral_confidence,
          quality_factor:            finalVerdict.quality_factor,
          reasoning: (() => {
            const r = narrator?.reasoning
            if (!r) return narratorFallback.reasoning
            if (Array.isArray(r)) return r.join(' ')
            if (typeof r === 'object' && r.text) return String(r.text)
            return String(r)
          })(),
        }

        // Update affected_asset in recommendations now that triage.affected_asset is resolved
        const { recommendations: finalRecommendations, provenance: finalProvenance }
          = buildDeterministicRecommendations(finalVerdict.signals, triage.affected_asset, acsObject)
        triage.recommendations = finalRecommendations
        triage.recommendation_provenance = finalProvenance

        // tactic (narrator free text) and mitre_tactic (deterministic lookup) may legitimately differ — no sync

        const requiredTriageFields = ['severity','classification','confidence','asset_is_critical','evidence','indicators','tactic','mitre_id','mitre_name','mitre_tactic','recommendations','reasoning']
        const missingFields = requiredTriageFields.filter(f => !(f in triage) || triage[f] === null || triage[f] === undefined)
        if (missingFields.length > 0) {
          console.error('[ARBITER] Output contract violation — missing fields:', missingFields)
          missingFields.forEach(f => {
            if (f === 'recommendations') {
              const { recommendations: fallbackRecs, provenance: fallbackProv }
                = buildDeterministicRecommendations(finalVerdict.signals, triage.affected_asset, acsObject)
              triage.recommendations = fallbackRecs
              triage.recommendation_provenance = fallbackProv
            }
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
          CORRELATED_INDICATOR_ACTIVITY: ['Multi-Asset Coordinated Attack'],
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

        // Write internal failure history for RFC1918 src_ip values.
        // These are excluded from the enrichment Redis namespace by
        // extractIPs() but required for ACS_LATERAL_MOVEMENT_CANDIDATE
        // failure-context tracking. Write only on failure events —
        // the lateral movement precondition requires prior failure evidence
        // before a success triggers the signal.
        const acsOutcomeForLateral =
          acsObject?.acs_data?.event_outcome?.value
        const acsSrcIpForLateralWrite =
          acsObject?.acs_data?.src_ip?.value
        const isRFC1918ForLateral = acsSrcIpForLateralWrite
          && /^10\.|^172\.(1[6-9]|2\d|3[01])\.|^192\.168\./i
             .test(acsSrcIpForLateralWrite)

        if (isRFC1918ForLateral && acsOutcomeForLateral === 'failure') {
          try {
            const internalWriteKey =
              `session:${safeSessionId}:internal_failure:${acsSrcIpForLateralWrite}`
            const existing = await redis.get(internalWriteKey)
            const prev = existing ?? { count: 0 }
            await redis.set(
              internalWriteKey,
              { count: prev.count + 1, lastSeen: new Date().toISOString() },
              { ex: REDIS_TTL }
            )
          } catch {
          }
        }

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
            verdictClass:             finalVerdict.verdictClass,
            verdictReliabilityClass:  finalVerdict.verdictReliabilityClass,
            behavioral_confidence:    finalVerdict.behavioral_confidence,
            quality_factor:           finalVerdict.quality_factor,
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