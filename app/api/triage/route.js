import Groq from 'groq-sdk'

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY })

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

// ── IP ENRICHMENT ─────────────────────────────────────────────────────────────
async function enrichIP(ip) {
  const results = {}

  const [abuseResult, vtResult, otxResult] = await Promise.allSettled([
    fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
      {
        method: 'GET',
        headers: {
          'Key': process.env.ABUSEIPDB_API_KEY,
          'Accept': 'application/json',
        }
      }
    ).then(async r => {
      const text = await r.text()
      console.log('[ARBITER] AbuseIPDB status:', r.status, 'body:', text)
      return JSON.parse(text)
    }),

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
  } else {
    results.abuseipdb = null
  }

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
  } else {
    results.virustotal = null
  }

  if (otxResult.status === 'fulfilled') {
    const d = otxResult.value
    results.otx = {
      pulseCount:    d?.pulse_info?.count ?? 0,
      tags:          d?.tags ?? [],
      malwareFamily: d?.pulse_info?.pulses?.[0]?.malware_families?.[0]?.display_name ?? null,
    }
  } else {
    results.otx = null
  }

  return results
}

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

function buildEnrichmentSummary(enrichment, ips) {
  if (!ips.length) return 'No public IPs detected in this alert.'
  return ips.map(ip => {
    const d = enrichment[ip]
    if (!d) return `IP ${ip}: enrichment unavailable`
    const lines = [`IP ${ip}:`]
    if (d.abuseipdb) lines.push(
      `  AbuseIPDB: score=${d.abuseipdb.score}/100 | reports=${d.abuseipdb.totalReports} | isp="${d.abuseipdb.isp}" | country=${d.abuseipdb.country} | tor=${d.abuseipdb.isTorNode} | usage="${d.abuseipdb.usageType}"`
    )
    if (d.virustotal) lines.push(
      `  VirusTotal: malicious=${d.virustotal.malicious} | suspicious=${d.virustotal.suspicious} | engines=${d.virustotal.total} | AS${d.virustotal.asn} "${d.virustotal.asOwner}" | network=${d.virustotal.network}`
    )
    if (d.otx) lines.push(
      `  OTX: pulses=${d.otx.pulseCount}${d.otx.malwareFamily ? ` | malware="${d.otx.malwareFamily}"` : ''}${d.otx.tags.length ? ` | tags=[${d.otx.tags.slice(0,6).join(', ')}]` : ''}`
    )
    return lines.join('\n')
  }).join('\n')
}

// ── SYSTEM PROMPT ─────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are ARBITER — a precision detection engineering triage engine. You analyze raw security alerts with threat enrichment data and return structured, accurate incident triage reports.

═══ WINDOWS EVENT ID → MITRE TECHNIQUE MAPPING ═══

4625 (Failed Logon):
  - %%2313 = Wrong password. Account EXISTS and is ACTIVE. Highest signal for brute force.
  - %%2304 = Account restrictions. Lockout evasion likely.
  - %%2310 = Account locked out by prior brute force.
  - Count >5 + same username + external IP = T1110.001 Password Guessing
  - Count >5 + multiple usernames + same IP = T1110.003 Password Spraying
  - LogonType 3 = Network. LogonType 10 = RDP. LogonType 2 = Interactive.
  - IMPORTANT: lsass.exe as ProcessName on 4625 is NORMAL behavior. Do NOT map to T1003.

4624 (Successful Logon):
  - Follows multiple 4625 events = T1110.001 succeeded → escalate to CRITICAL immediately
  - Anomalous hours + external IP = T1078 Valid Accounts
  - LogonType 3 + NTLM auth = consider T1550.002 Pass the Hash

4648 (Explicit Credential Logon):
  - Non-interactive context = T1550.002 or T1078

4688 / Sysmon Event 1 (Process Created):
  - cmd.exe, powershell.exe, wscript.exe, cscript.exe = T1059 subtechniques
  - certutil.exe -decode or -urlcache = T1140 or T1105 Ingress Tool Transfer
  - regsvr32.exe + remote URL = T1218.010 Signed Binary Proxy Execution
  - mshta.exe + .hta or URL = T1218.005
  - rundll32.exe + suspicious DLL path = T1218.011
  - schtasks.exe /create = T1053.005
  - net.exe user /add or localgroup = T1136.001 or T1098
  - whoami, ipconfig, net view, nltest = T1082 / T1016 Discovery
  - Encoded PowerShell (-enc, -encodedCommand, IEX) = T1059.001 + T1027
  - PsExec, WMI, DCOM lateral tool use = T1021 subtechniques

4698 / 4702 (Scheduled Task):
  - T1053.005 Scheduled Task/Job

4720 / 4722 (Account Created/Enabled):
  - T1136.001 Create Local Account

4732 / 4728 (Group Membership Changed):
  - T1098 Account Manipulation

4776 (NTLM Credential Validation):
  - Lateral movement context = T1550.002

4697 / 7045 (Service Installed):
  - T1543.003 Windows Service

4663 / 4656 (Object Access):
  - Target: SAM, NTDS.dit, lsass memory = T1003 OS Credential Dumping
  - High file count + short window = T1005 Data from Local System

1102 / 4719 (Audit Log Cleared):
  - T1070.001 Clear Windows Event Logs
  - ALWAYS HIGH severity minimum. Indicates attacker covering tracks.

4104 (PowerShell Script Block Logging):
  - Invoke-Mimikatz, Invoke-BloodHound, Empire, Cobalt Strike artifacts = T1059.001 CRITICAL
  - Download cradles (IEX, WebClient, DownloadString) = T1059.001 + T1105

Sysmon 3 (Network Connection):
  - System process + outbound to non-standard port = T1071 Application Layer Protocol
  - Regular interval connections = T1071 + note potential C2 beaconing pattern

═══ SEVERITY DETERMINATION RULES ═══

CRITICAL — escalate immediately if ANY of:
  - Successful logon (4624) following brute force pattern (prior 4625 sequence)
  - Domain Controller targeted (DC, -DC-, CORP-DC, PDC, BDC in hostname)
  - Direct access to NTDS.dit, SAM, or LSASS process memory
  - Audit log cleared (anti-forensics, attacker has established access)
  - Known ransomware indicators: shadow copy deletion, vssadmin, wbadmin, mass encryption
  - OTX malware family identified
  - Lateral movement + privilege escalation in same alert context
  - Data staged for or in active exfiltration to external IP

HIGH — immediate investigation required if ANY of:
  - Service/backup accounts targeted (svc_, backup_, _svc, sa_, admin_)
  - Source confirmed as Tor node (isTorNode=true) or bulletproof hosting ASN
  - AbuseIPDB score ≥ 80
  - OTX pulses > 5
  - Persistence mechanism established (scheduled task, service, registry run key)
  - Encoded/obfuscated command execution
  - Lateral movement to non-DC target
  - Multiple failed logons against privileged account from external source

MEDIUM — investigate within shift if ANY of:
  - AbuseIPDB score 40–79
  - Single failed logon from external IP, clean enrichment
  - Discovery phase commands (whoami, ipconfig, net view) in isolation
  - Suspicious child process from legitimate parent, first occurrence
  - OTX pulses 1–5

LOW — log and monitor:
  - Clean enrichment across all three sources
  - Single event, no repetition, known benign explanation plausible
  - Policy violation without malicious indicators

═══ ENRICHMENT WEIGHTING ═══
AbuseIPDB ≥ 80: confirmed malicious source. Always state the score. Raise severity one level if not already CRITICAL.
AbuseIPDB ≥ 40: suspicious. Do not lower severity.
isTorNode = true: anonymization active. Attacker concealing origin. Always note this.
VirusTotal malicious > 0: cross-validated threat. Cite the detection count and engine total.
OTX pulses > 0: known threat actor infrastructure. State pulse count. Name malware family if present.
All three sources confirm threat: confidence ≥ 90.
All three sources clean: consider benign explanation. Reduce confidence to 50–65.

═══ ASSET CRITICALITY RULES ═══
asset_is_critical = true:
  - Domain Controllers: hostname contains DC, -DC-, PDC, BDC, CORP-DC
  - Backup systems: backup, bkp, veeam, commvault in hostname or username
  - Database servers: SQL, DB, oracle, postgres, mysql in hostname
  - Targets: NTDS.dit, SAM database, krbtgt account

═══ RECOMMENDATION STANDARDS ═══
Each of the 5 recommendations must:
  1. Reference a specific indicator from this alert (the actual IP, username, hostname, event code)
  2. Be executable by a Tier 1–2 analyst right now without further context
  3. Be ordered: containment first → investigation second → validation third → hardening last
  4. Never be generic ("monitor the system", "review permissions" = REJECTED)

Examples:
  GOOD: "Block 185.220.101.47/32 at perimeter firewall and confirm block by monitoring 4625 stream from CORP-DC-01 for cessation"
  BAD:  "Block the malicious IP address at the firewall"

  GOOD: "Run: net user svc_backup /domain — verify last successful logon timestamp and source IP against known baseline"
  BAD:  "Audit the affected service account for suspicious activity"

═══ REASONING STANDARDS ═══
Write exactly as a senior SOC analyst writes an escalation case note.
- 2–4 sentences maximum
- Every sentence must reference a specific, named indicator from the alert or enrichment
- State conclusions directly. "This is consistent with X" not "This could indicate X"
- The final sentence must state the single most important action or risk
- Reference event IDs, failure reason codes, IP scores, pulse counts, asset type, count and frequency

GOOD reasoning example:
"47 consecutive 4625/%%2313 events against svc_backup from AS53667 (isTorNode=true, AbuseIPDB 98/100, 847 reports) in 180 seconds with no corresponding 4740 lockout event is consistent with automated password spraying against a misconfigured domain controller. The absence of lockout after 47 failures indicates the lockout threshold is not enforced on CORP-DC-01. Priority: isolate DC from the /32 source and audit for any 4624 events from 185.220.101.47 before closing."

BAD reasoning example:
"This alert shows suspicious activity that could potentially indicate a brute force attack. The IP address has a high abuse score. It is recommended to investigate further."

═══ OUTPUT ═══
A single valid JSON object. No markdown. No backticks. No preamble. No explanation after. Exactly these fields:
{
  "classification": string (specific attack technique name, not generic category),
  "tactic": string (MITRE tactic name, e.g. "Credential Access"),
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence": number 0–100,
  "mitre_id": string (most specific subtechnique, e.g. T1110.001 not T1110),
  "mitre_name": string,
  "mitre_tactic": string,
  "affected_asset": string (actual hostname from alert, not generic),
  "asset_is_critical": boolean,
  "recommendations": string[] (exactly 5 items, specific, ordered by urgency, each under 120 characters),
  "reasoning": string (2–4 sentences, dense with specific named indicators, zero filler),
  "evidence": string[] (exactly 3–6 items, each being a specific raw field from the alert that directly drove this verdict, formatted as "FIELD=VALUE" exactly as it appears in the raw alert — e.g. "EventCode=4625", "FailureReason=%%2313", "Count=47", "IpAddress=185.220.101.47". Only include fields that actually influenced the classification, severity, or MITRE mapping. Never include generic fields like timestamps unless they were specifically relevant.)
}`

// ── ROUTE HANDLER ─────────────────────────────────────────────────────────────
export async function POST(request) {
  const startTime = Date.now()

  try {
    const { alertText } = await request.json()
    if (!alertText?.trim() || alertText.trim().length < 10) {
      return Response.json({ error: 'Alert text is too short.' }, { status: 400 })
    }

    const parsedAlert = parseAlert(alertText)
    const truncatedAlert = (alertText.length > 3000
      ? alertText.slice(0, 3000) + '\n[TRUNCATED]'
      : alertText).replace(/"/g, "'")
    const ips = extractIPs(alertText)

    const enrichment = {}
    if (ips.length > 0) {
      const enrichResults = await Promise.all(ips.map(ip => enrichIP(ip)))
      ips.forEach((ip, i) => { enrichment[ip] = enrichResults[i] })
    }

    const enrichmentSummary = buildEnrichmentSummary(enrichment, ips)

    const parsedContext = Object.entries(parsedAlert)
      .filter(([_, v]) => v !== null)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n')

    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      temperature: 0.1,
      max_tokens: 4000,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        {
          role: 'user',
          content: `ALERT TYPE: ${parsedAlert.alertType}

RAW ALERT:
${truncatedAlert}

PRE-PARSED FIELDS:
${parsedContext || 'No structured fields extracted'}

THREAT ENRICHMENT:
${enrichmentSummary}

Analyze this alert. Apply the MITRE mapping rules precisely. Weight the enrichment data. Return only the JSON triage object.`
        }
      ]
    })

    const raw = completion.choices[0]?.message?.content ?? ''
    const jsonMatch = raw.match(/\{[\s\S]*\}/)
    if (!jsonMatch) throw new Error('Model returned invalid JSON structure')

    let triage
    try {
      triage = JSON.parse(jsonMatch[0])
    } catch {
      throw new Error('Failed to parse model JSON output')
    }

    const required = ['classification','tactic','severity','confidence','mitre_id','mitre_name','mitre_tactic','affected_asset','asset_is_critical','recommendations','reasoning']
    const missing = required.filter(f => !(f in triage))
    if (missing.length) throw new Error(`Model response missing fields: ${missing.join(', ')}`)

    if (!Array.isArray(triage.recommendations) || triage.recommendations.length !== 5) {
      triage.recommendations = (triage.recommendations ?? []).slice(0, 5)
      while (triage.recommendations.length < 5) {
        triage.recommendations.push('Review alert context and escalate if indicators persist.')
      }
    }

    return Response.json({
      triage,
      enrichment,
      ips,
      meta: {
        processingTime:     Date.now() - startTime,
        enrichmentSources:  ips.length > 0 ? ['abuseipdb', 'virustotal', 'otx'] : [],
        alertType:          parsedAlert.alertType,
        parsedFields:       Object.keys(parsedAlert).filter(k => parsedAlert[k] !== null),
      }
    })

  } catch (err) {
    console.error('[ARBITER] Triage error:', err)
    return Response.json({
      error: err.message ?? 'Triage failed. Verify API keys and alert format.'
    }, { status: 500 })
  }
}