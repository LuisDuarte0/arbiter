# ARBITER — Architecture

In this document I will explain the pipeline decisions behind ARBITER: what runs in what order, why each component exists, and what tradeoffs were made.

---

## Pipeline Overview

```
Raw Alert Text
      │
      ▼
┌─────────────────────────────────────┐
│  1. PRE-PARSER                      │
│  Regex field extraction             │
│  Runs before the LLM sees anything  │
└──────────────────┬──────────────────┘
                   │
      ┌────────────┴────────────┐
      ▼                         ▼
┌───────────────┐    ┌──────────────────────┐
│ 2. LLM TRIAGE │    │ 3. IP ENRICHMENT     │
│ Groq          │    │ AbuseIPDB            │
│ Llama 3.3 70B │    │ VirusTotal           │
│ 200-line      │    │ AlienVault OTX       │
│ system prompt │    │ (parallel, async)    │
└───────┬───────┘    └──────────┬───────────┘
        │                       │
        └──────────┬────────────┘
                   ▼
┌─────────────────────────────────────┐
│  4. VALIDATION                      │
│  Required field check               │
│  JSON parse guard                   │
│  Severity normalization             │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  5. REACT UI                        │
│  Verdict hero · Evidence chips      │
│  MITRE grid · Recommendations       │
│  Threat intel panel · Audit log     │
│  Containment playbook · PDF export  │
└─────────────────────────────────────┘
```

---

## Component Decisions

### 1. Pre-Parser — Why Before the LLM?

The pre-parser runs regex extraction on the raw alert *before* the LLM receives it. It pulls structured fields: EventCode, LogonType, FailureReason, TargetUserName, ProcessName, CommandLine, WorkstationName, IpAddress, Count.

**Why not let the LLM parse the alert itself?**

Two reasons. First, LLMs are inconsistent at extracting structured fields from noisy text — they hallucinate field names, merge values, and miss Windows-specific formatting. The regex is deterministic and fast.

Second, the pre-parsed fields are passed *separately* into the prompt alongside the raw alert. This gives the LLM two representations of the same data: the structured extraction it can reason over precisely, and the raw text it can use for context. Output quality improves measurably.

---

### 2. LLM — Why Groq + Llama 3.3 70B?

**Why Groq over OpenAI or Anthropic?**

Latency. Groq's hardware inference is 5-10x faster than standard API endpoints. For a triage tool where an analyst is waiting for output, sub-3-second inference matters. The tradeoff is a daily token limit on the free tier (100k tokens/day), which is sufficient for development and demo use.

**Why Llama 3.3 70B over a smaller model?**

The 70B model reliably follows the structured JSON output format defined in the system prompt, even for complex alerts with multiple event codes, enrichment data, and long command lines. Smaller models (8B, 13B) frequently truncate output, hallucinate MITRE IDs, or break JSON structure.

**Why not Claude or GPT-4o?**

Cost and latency for a portfolio project on Vercel's free tier. The architecture is model-agnostic — swapping the model is a one-line change in `app/api/triage/route.js`. The moat is the prompt, not the model.

---

### 3. System Prompt — The Real Moat

The 200-line system prompt is the core engineering work in ARBITER. It encodes domain knowledge that generic LLM prompts don't have:

**Event ID → MITRE subtechnique mappings**
- `4625 + %%2313 + single username` → T1110.001 (Password Guessing)
- `4625 + %%2313 + multiple usernames` → T1110.003 (Password Spraying)
- `4625 + %%2313 + high Count` → raises severity to CRITICAL
- `4663 + ntds.dit + ntdsutil.exe` → T1003.003 (NTDS)
- `4698 + IEX/DownloadString` → T1053.005 (Scheduled Task)
- `1102` → T1070.001 (Clear Windows Event Logs)
- `4104 + Invoke-Mimikatz` → T1003 (OS Credential Dumping)

**Failure reason code semantics**
- `%%2313` — account exists, wrong password. Highest signal for active credential attack.
- `%%2304` — account restrictions. Possible lockout evasion.
- `%%2305` — account locked out. Confirms ongoing brute force.

**Noise suppression rules**
- `lsass.exe` as ProcessName on a 4625 event is normal auth behavior. Not T1003.
- A single failed logon (Count=1) from an internal IP is LOW by default.
- Scheduled tasks created by known admin binaries (defrag.exe, sfc.exe) are LOW.

**Asset criticality rules**
- Hostnames containing `DC`, `ADDC`, `PDC`, `GC` → Domain Controller → `asset_is_critical: true`
- Hostnames containing `BACKUP`, `BKUP` → Backup server → `asset_is_critical: true`
- ObjectName targeting `ntds.dit`, `SYSTEM`, `SAM` → critical file access

**Enrichment weighting**
- AbuseIPDB score ≥ 80 → raise severity one level, cite score by name
- `isTorNode: true` → add anonymization note to reasoning
- VirusTotal malicious detections > 0 → cite count and total engines
- OTX pulseCount > 10 → cite malware family name if present
- If all three sources confirm threat → confidence floors at 90

**Recommendation quality standard**
Every recommendation must reference a specific named indicator from the alert — the actual IP address, hostname, username, or event code. Generic recommendations ("monitor the system", "check logs") are rejected at the prompt level.

---

### 4. IP Enrichment — Why Parallel?

The three enrichment calls (AbuseIPDB, VirusTotal, OTX) run simultaneously via `Promise.all`, not sequentially. On a slow connection, sequential calls would add 3-6 seconds of latency. Parallel execution keeps total enrichment time close to the slowest single call (~1-2 seconds).

**Why these three sources?**

Each covers a different signal type:
- **AbuseIPDB** — reputation score and report frequency. Best signal for active threat actors.
- **VirusTotal** — malware engine consensus. Best signal for known malicious infrastructure.
- **AlienVault OTX** — threat intelligence community pulses and malware family attribution. Best for named threat actor and campaign context.

Together they provide breadth. A clean score on one source doesn't exonerate an IP if the other two flag it.

**What if no public IPs are present?**

The enrichment step is skipped entirely. The LLM receives a note that no public IPs were detected and adjusts its reasoning accordingly. Internal IP addresses (RFC 1918) are excluded from enrichment.

---

### 5. Evidence Chips — Why Explainability Matters

Every triage result includes an `evidence` array: the specific raw log fields that drove the verdict. These are rendered as chips in the UI and included in PDF exports.

This is not cosmetic. An analyst cannot act on AI output they cannot audit. The evidence chips answer the question "why did ARBITER say CRITICAL?" by showing exactly which fields were weighted — `EventCode=4663`, `ObjectName=C:\Windows\NTDS\ntds.dit`, `ProcessName=ntdsutil.exe` — without requiring the analyst to re-read the full raw alert.

The system prompt enforces this: evidence items must be actual `FIELD=VALUE` pairs from the raw alert, never generic descriptions.

---

### 6. Containment Playbook — Triage to Response

The containment script generator is a second LLM call triggered manually after triage. It receives the full triage output — classification, MITRE ID, affected asset, evidence fields, enrichment data — and generates three script types:

- **PowerShell** — firewall rules, account actions, session termination, event log queries
- **CMD/Net** — quick Tier 1 commands for environments without PowerShell access
- **Investigation** — Get-WinEvent queries scoped to the specific event ID, hostname, and timeframe from the alert

All values are derived from the actual triage output. No placeholder syntax. The system prompt explicitly forbids invented values.

Warnings are categorized automatically: phrases indicating irreversible actions, production impact, or network isolation are classified as Critical Blockers (red). General security recommendations are classified separately (yellow).

---

### 7. Deployment — Why Vercel?

ARBITER's API routes are Next.js serverless functions. Vercel's free tier supports this without configuration — no Docker, no server management, no cold start tuning beyond what Next.js provides by default.

**Limitations:**
- Serverless function timeout: 10 seconds on free tier. Heavy alerts with slow enrichment responses occasionally approach this limit.
- No persistent storage: audit log and session history live in the browser's localStorage. There is no backend database.
- Groq free tier: 100,000 tokens/day. Heavy use exhausts this within a day of intensive testing.

None of these are architectural flaws — they are the correct tradeoffs for a portfolio project that needs to run reliably at zero cost.

---

## File Structure

```
arbiter/
├── app/
│   ├── api/
│   │   ├── triage/
│   │   │   └── route.js          # Pre-parser, enrichment, LLM, validation
│   │   └── containment/
│   │       └── route.js          # Containment playbook generator
│   ├── components/
│   │   ├── Header.js             # Case ID, audit log, NEW ANALYSIS button
│   │   ├── AlertQueue.js         # Session history with search
│   │   ├── AnalysisPanel.js      # Alert input + two-column triage output
│   │   ├── IntelPanel.js         # Threat intelligence enrichment panel
│   │   ├── AuditLog.js           # Persistent audit log + MITRE coverage matrix
│   │   ├── ContainmentModal.js   # Playbook modal with execution metadata sidebar
│   │   └── ExportPDF.js          # Client-side PDF generation (jsPDF)
│   ├── globals.css
│   ├── layout.js
│   └── page.js
└── .env.local                    # API keys — never committed
```

---

## What This Is Not

ARBITER is not a production SIEM replacement. It does not ingest log streams, manage alert queues at scale, or integrate with ticketing systems. It is a demonstration of detection engineering thinking applied to a full-stack project: the ability to encode domain knowledge as executable prompt logic, integrate threat intelligence APIs, and build a UI that an analyst would actually want to use.

The ground-truth test suite (in progress) will measure classification accuracy and confidence score calibration across a labeled set of 25-30 alerts spanning CRITICAL through LOW severity and multiple MITRE tactics.

---

*Built by Luis Duarte*
*[linkedin.com/in/luis-duarte-560993291](https://linkedin.com/in/luis-duarte-560993291) · luiscmduarte077@gmail.com*
