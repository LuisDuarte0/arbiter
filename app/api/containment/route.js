export const maxDuration = 15
import Groq from 'groq-sdk'

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY })

const CONTAINMENT_PROMPT = `You are ARBITER's containment script engine. Based on a completed triage report, generate precise, executable Windows containment and investigation commands.

RULES:
- Every command must use actual values from the triage (real IP, real username, real hostname)
- Never invent values not present in the triage
- Commands must be immediately executable by a Tier 1-2 analyst
- Label each section clearly
- Include brief inline comments explaining what each command does
- If a value is unknown (e.g. no IP detected), omit that command entirely rather than using a placeholder

OUTPUT: A single valid JSON object with exactly these fields:
{
  "powershell": string (PowerShell commands as a single multiline string),
  "cmd": string (CMD/net commands as a single multiline string),
  "investigation": string (Event Log queries and investigation commands as a single multiline string),
  "warnings": string[] (1-3 critical warnings the analyst must read before executing),
  "scope": string (one sentence describing what these commands contain and target)
}

No markdown. No backticks around the JSON. No preamble. Output only the JSON object.`

export async function POST(request) {
  try {
    const { triage, enrichment, ips } = await request.json()

    if (!triage) {
      return Response.json({ error: 'No triage data provided.' }, { status: 400 })
    }

    const primaryIP = ips?.[0] ?? null
    const abuseScore = primaryIP ? enrichment?.[primaryIP]?.abuseipdb?.score : null
    const isTor = primaryIP ? enrichment?.[primaryIP]?.abuseipdb?.isTorNode : null

    const triageSummary = `
TRIAGE RESULT:
Classification: ${triage.classification}
MITRE: ${triage.mitre_id} — ${triage.mitre_name}
Tactic: ${triage.tactic}
Severity: ${triage.severity}
Confidence: ${triage.confidence}%
Affected Asset: ${triage.affected_asset} (Critical: ${triage.asset_is_critical})
${primaryIP ? `Source IP: ${primaryIP}${abuseScore != null ? ` (AbuseIPDB: ${abuseScore}/100)` : ''}${isTor ? ' — Tor Exit Node' : ''}` : 'No public IPs detected.'}

RECOMMENDATIONS FROM TRIAGE:
${triage.recommendations.map((r, i) => `${i + 1}. ${r}`).join('\n')}

EVIDENCE FIELDS:
${triage.evidence?.join('\n') ?? 'None recorded'}
`

    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      temperature: 0.1,
      max_tokens: 2000,
      messages: [
        { role: 'system', content: CONTAINMENT_PROMPT },
        {
          role: 'user',
          content: `Generate Windows containment and investigation commands for this triage result.\n\n${triageSummary}\n\nUse only the real values above. Return only the JSON object.`
        }
      ]
    })

    const raw = completion.choices[0]?.message?.content ?? ''
    const jsonMatch = raw.match(/\{[\s\S]*\}/)
    if (!jsonMatch) throw new Error('Model returned invalid JSON')

    const scripts = JSON.parse(jsonMatch[0])

    return Response.json({ scripts })

  } catch (err) {
    console.error('[ARBITER] Containment error:', err)
    const is429 = err?.status === 429 || err?.message?.includes('429')
    return Response.json({
      error: is429
        ? 'API rate limit reached. Please wait a few minutes and try again.'
        : err.message ?? 'Containment script generation failed.'
    }, { status: 500 })
  }
}