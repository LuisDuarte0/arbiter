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

async function getRedisContext(ips, username) {
  const keys = []
  if (ips.length)  ips.forEach(ip => keys.push(`ip:${ip}`))
  if (username)    keys.push(`user:${username}`)
  if (!keys.length) return null

  try {
    const results = await Promise.all(keys.map(k => redis.get(k)))
    const hits = results
      .map((r, i) => r ? { key: keys[i], ...r } : null)
      .filter(Boolean)
    if (!hits.length) return null
    return hits
  } catch { return null }
}

async function writeRedisContext(ips, username, triage, caseId) {
  const now = Date.now()
  const entry = {
    caseId,
    severity:        triage.severity,
    classification:  triage.classification,
    affectedAsset:   triage.affected_asset,
    timestamp:       now,
  }

  const writes = []

  ips.forEach(ip => {
    const key = `ip:${ip}`
    writes.push(
      redis.get(key).then(existing => {
        const prev = existing ?? { count: 0, cases: [], assets: [] }
        const updated = {
          ...entry,
          count:  prev.count + 1,
          cases:  [caseId, ...(prev.cases ?? [])].slice(0, 10),
          assets: [...new Set([triage.affected_asset, ...(prev.assets ?? [])])].slice(0, 10),
        }
        return redis.set(key, updated, { ex: REDIS_TTL })
      })
    )
  })

  if (username && username !== 'SYSTEM' && !username.includes('$')) {
    const key = `user:${username}`
    writes.push(
      redis.get(key).then(existing => {
        const prev = existing ?? { count: 0, cases: [], assets: [] }
        const updated = {
          ...entry,
          count:  prev.count + 1,
          cases:  [caseId, ...(prev.cases ?? [])].slice(0, 10),
          assets: [...new Set([triage.affected_asset, ...(prev.assets ?? [])])].slice(0, 10),
        }
        return redis.set(key, updated, { ex: REDIS_TTL })
      })
    )
  }

  try { await Promise.all(writes) } catch { /* non-blocking */ }
}

function buildRedisContextSummary(hits) {
  if (!hits?.length) return null
  return hits.map(h => {
    const age = Math.round((Date.now() - h.timestamp) / 60000)
    const indicator = h.key.startsWith('ip:') ? `IP ${h.key.slice(3)}` : `User ${h.key.slice(5)}`
    return `${indicator}: seen ${h.count}× in last 24h | last severity=${h.severity} | assets=[${(h.assets ?? []).join(', ')}] | ${age}min ago | cases=[${(h.cases ?? []).slice(0,3).join(', ')}]`
  }).join('\n')
}

// ── ALERT PRE-PARSER ──────────────────────────────────────────────────────────
function parseAlert(text) {
  const get = (pattern) => text.match(pattern)?.[1]?.trim() ?? null
  return {
    eventId:       get(/EventCode[=:\s]+(\d+)/i),
    logonType:     get(/LogonType[=:\s]+(\d+)/i),
    failureReason: get(/FailureReason[=:\s]+(%%\d+)/i),
    username:      get(/(?:TargetUserName|SubjectUserName|Username|User)[=:\s]+(\S+)/i),
    domain:        get(/(?:TargetDomainName|Domain)[=:\s]+(\S+)/i),
    processName:   get(/ProcessName[=:\s]+(.+?)(?:\r?\n|$)/i),
    commandLine:   get(/(?:CommandLine|ProcessCommandLine)[=:\s]+(.+?)(?:\r?\n|$)/i),
    asset:         get(/(?:WorkstationName|ComputerName|Hostname|host)[=:\s]+(\S+)/i),
    allAssets:     [...new Set((text.match(/(?:WorkstationName|ComputerName)[=:\s]+(\S+)/gi) ?? []).map(m => m.trim().split(/[=:\s]+/).pop()))].join(', '),
    allEventCodes: [...new Set((text.match(/EventCode[=:\s]+(\d+)/gi) ?? []).map(m => m.trim().split(/[=:\s]+/).pop()))].join(', '),
    count:         get(/Count[=:\s]+(\d+)/i),
    fileHash:      get(/(?:MD5|SHA1|SHA256|Hashes)[=:\s]+([a-fA-F0-9]{32,64})/i),
    parentProcess: get(/(?:ParentProcessName|ParentImage)[=:\s]+(.+?)(?:\r?\n|$)/i),
    alertType:     detectAlertType(text),
  }
}

function detectAlertType(text) {
  if (/EventCode|Security-Auditing|Microsoft-Windows/i.test(text)) return 'Windows Security Event'
  if (/CEF:|syslog|facility/i.test(text)) return 'Syslog/CEF'
  if (/eventSource.*amazonaws|CloudTrail/i.test(text)) return 'AWS CloudTrail'
  if (/crowdstrike|defender|sentinel|edr/i.test(text)) return 'EDR Alert'
  if (/\"alert\"|\"rule\"|\"signature\"/i.test(text)) return 'IDS/IPS Alert'
  return 'Generic Log'
}

// ── IP EXTRACTION ─────────────────────────────────────────────────────────────
function extractIPs(text) {
  return [...new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [])].filter(ip => {
    const p = ip.split('.').map(Number)
    return !p.some(n => n > 255)
      && p[0] !== 127 && p[0] !== 10 && p[0] !== 0
      && !(p[0] === 192 && p[1] === 168)
      && !(p[0] === 172 && p[1] >= 16 && p[1] <= 31)
      && !(p[0] === 169 && p[1] === 254)
  })
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
// Pre-computes enrichment consensus and weight signals before LLM sees the data.
// This moves threshold logic from the non-deterministic LLM into deterministic JS.

function buildEnrichmentJudgment(enrichment, ips) {
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
    if (!d) return { ip, verdict: 'UNAVAILABLE', signals: [], modifier: 0, blockAllowed: false }

    const signals = []
    let threatScore = 0
    let blockAllowed = false

    // ── AbuseIPDB ─────────────────────────────────────────────────────────────
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

    // ── VirusTotal ────────────────────────────────────────────────────────────
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

    // ── OTX ──────────────────────────────────────────────────────────────────
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

    // ── Consensus Verdict ─────────────────────────────────────────────────────
    let verdict
    let modifier
    if (threatScore >= 60) {
      verdict = 'CONFIRMED_MALICIOUS'
      modifier = +15
    } else if (threatScore >= 25) {
      verdict = 'SUSPICIOUS'
      modifier = +5
    } else if (threatScore >= 5) {
      verdict = 'MIXED_SIGNALS'
      modifier = -10
    } else {
      verdict = 'CLEAN'
      modifier = -20
    }

    // Check for conflicting signals (one source high, others clean)
    const hasConflict = d.abuseipdb && d.virustotal && d.otx &&
      ((d.abuseipdb.score >= 80 && d.virustotal.malicious === 0 && d.otx.pulseCount === 0) ||
       (d.abuseipdb.score === 0 && d.virustotal.malicious >= 10) ||
       (d.abuseipdb.score === 0 && d.otx.pulseCount > 20 && d.virustotal.malicious === 0))

    if (hasConflict) {
      signals.push(`CONFLICTING SOURCES: sources disagree — treat as SUSPICIOUS, do not escalate to CRITICAL on enrichment alone`)
      modifier = -5
    }

    return {
      ip,
      verdict,
      signals,
      modifier,
      blockAllowed,
      threatScore,
      raw: {
        abuseipdb: d.abuseipdb,
        virustotal: d.virustotal,
        otx: d.otx,
      }
    }
  })

  const dominantVerdict = ipJudgments.reduce((acc, j) => {
    const order = ['CONFIRMED_MALICIOUS', 'SUSPICIOUS', 'MIXED_SIGNALS', 'CLEAN', 'UNAVAILABLE']
    return order.indexOf(j.verdict) < order.indexOf(acc) ? j.verdict : acc
  }, 'UNAVAILABLE')

  const blockAllowed = ipJudgments.some(j => j.blockAllowed)
  const totalModifier = ipJudgments.reduce((sum, j) => sum + j.modifier, 0)

  const summaryLines = ipJudgments.map(j => {
    return [
      `IP ${j.ip} — VERDICT: ${j.verdict} (threat score: ${j.threatScore})`,
      ...j.signals.map(s => `  • ${s}`)
    ].join('\n')
  })

  return {
    summary: summaryLines.join('\n\n'),
    judgment: dominantVerdict,
    blockRecommendationAllowed: blockAllowed,
    confidenceModifier: Math.max(-25, Math.min(+20, totalModifier)),
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
        const { alertText } = await request.json()

        if (!alertText?.trim() || alertText.trim().length < 10) {
          send(controller, 'error', { message: 'Alert text is too short.' })
          controller.close()
          return
        }

        const parsedAlert = parseAlert(alertText)
        const truncatedAlert = (alertText.length > 3000
          ? alertText.slice(0, 3000) + '\n[TRUNCATED]'
          : alertText).replace(/"/g, "'")
        const ips = extractIPs(alertText)

        // ── PHASE 1: ENRICHMENT ──────────────────────────────────────────────
        send(controller, 'status', { phase: 'enriching', message: 'Enriching threat intelligence...' })

        const enrichment = {}
        if (ips.length > 0) {
          const enrichResults = await Promise.all(ips.map(ip => enrichIP(ip)))
          ips.forEach((ip, i) => { enrichment[ip] = enrichResults[i] })
        }

        // Stream enrichment data immediately so UI can populate intel panel
        send(controller, 'enrichment', { enrichment, ips })

        // ── REDIS: READ HISTORICAL CONTEXT ───────────────────────────────────
        const redisHits    = await getRedisContext(ips, parsedAlert.username)
        const redisContext = buildRedisContextSummary(redisHits)
        const isCorrelated = !!(redisHits?.length)

        if (isCorrelated) {
          send(controller, 'correlation', { hits: redisHits, summary: redisContext })
        }

        // ── PHASE 2: LLM TRIAGE WITH FULL ENRICHMENT CONTEXT ────────────────
        send(controller, 'status', { phase: 'analyzing', message: 'ARBITER is analyzing your alert...' })

        const enrichmentJudgment = buildEnrichmentJudgment(enrichment, ips)
        const parsedContext = Object.entries(parsedAlert)
          .filter(([_, v]) => v !== null)
          .map(([k, v]) => `${k}: ${v}`)
          .join('\n')

        const groqStream = await groq.chat.completions.create({
          model: 'llama-3.3-70b-versatile',
          temperature: 0.1,
          max_tokens: 3000,
          stream: false,
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            {
              role: 'user',
              content: `ALERT TYPE: ${parsedAlert.alertType}

RAW ALERT:
${truncatedAlert}

PRE-PARSED FIELDS:
${parsedContext || 'No structured fields extracted'}

ENRICHMENT JUDGMENT:
${enrichmentJudgment.summary}
VERDICT: ${enrichmentJudgment.judgment}
blockRecommendationAllowed: ${enrichmentJudgment.blockRecommendationAllowed}
confidenceModifier: ${enrichmentJudgment.confidenceModifier > 0 ? '+' : ''}${enrichmentJudgment.confidenceModifier}

${redisContext ? `TEMPORAL CORRELATION (ARBITER MEMORY — last 24h):
${redisContext}
IMPORTANT: Reference this historical activity in your reasoning. If the same IP or user appears multiple times, state the count and time elapsed.
` : ''}Analyze this alert. Enumerate technical facts first. Apply MITRE mapping rules precisely. Return only the JSON triage object.`
            }
          ]
        })

        const raw = groqStream.choices[0]?.message?.content ?? ''

        // Parse and validate
        const jsonMatch = raw.match(/\{[\s\S]*\}/)
        if (!jsonMatch) throw new Error('Model returned invalid JSON structure')

        let triage
        try {
          triage = JSON.parse(jsonMatch[0])
        } catch {
          throw new Error('Failed to parse model JSON output')
        }

        const required = ['indicators','classification','tactic','severity','confidence','mitre_id','mitre_name','mitre_tactic','affected_asset','asset_is_critical','recommendations','reasoning']
        const missing = required.filter(f => !(f in triage))
        if (missing.length) throw new Error(`Model response missing fields: ${missing.join(', ')}`)

          if (Array.isArray(triage.reasoning)) {
            triage.reasoning = triage.reasoning.join(' ')
          }

        if (!Array.isArray(triage.recommendations) || triage.recommendations.length !== 5) {
          triage.recommendations = (triage.recommendations ?? []).slice(0, 5)
          while (triage.recommendations.length < 5) {
            triage.recommendations.push('Review alert context and escalate if indicators persist.')
          }
        }

        // Write to Redis after successful triage
        const caseId = `ARB-${startTime}`
        await writeRedisContext(ips, parsedAlert.username, triage, caseId)

        // Stream final triage result
        send(controller, 'triage', {
          triage,
          enrichment,
          ips,
          correlation: isCorrelated ? { hits: redisHits, summary: redisContext } : null,
          meta: {
            processingTime:    Date.now() - startTime,
            enrichmentSources: ips.length > 0 ? ['abuseipdb', 'virustotal', 'otx'] : [],
            alertType:         parsedAlert.alertType,
            parsedFields:      Object.keys(parsedAlert).filter(k => parsedAlert[k] !== null),
            correlated:        isCorrelated,
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