# ARBITER

**AI-powered SOC alert triage.** Paste a raw security alert. Get a structured incident report in under ten seconds.

→ **[Live Demo](https://arbiter-security.vercel.app)**

---

## What it does

Tier 1 SOC analysts spend a significant portion of their shift doing the same thing: read an alert, look up the IP, check if the account is sensitive, map it to a MITRE technique, write up a recommendation. ARBITER automates the mechanical parts of that workflow.

Paste any raw alert — Windows Security Event, Syslog/CEF, EDR output, IDS signature. ARBITER:

1. Parses the alert and extracts structured indicators
2. Enriches public IPs against three threat intelligence sources simultaneously
3. Maps the behavior to a specific MITRE ATT&CK subtechnique
4. Returns a full triage report: classification, severity, confidence score, five prioritized recommendations, and analyst-grade reasoning

The output reads like a senior analyst wrote it because the intelligence is in the prompt — not generic AI summarization.

---

## Sample output

Input:
```
EventCode=4625
LogonType=3
TargetUserName=svc_backup
FailureReason=%%2313
IpAddress=185.220.101.47
WorkstationName=CORP-DC-01
Count=47
```

Output:
- **Classification:** Password Spraying
- **MITRE:** T1110.003 — Credential Access
- **Severity:** CRITICAL
- **Confidence:** 95%
- **Asset:** CORP-DC-01 (Domain Controller — Critical Asset)
- **Reasoning:** *47 consecutive 4625/%%2313 events against svc_backup from AS60729 (VirusTotal malicious=15, OTX pulses=50) in a short time frame is consistent with automated password spraying against a misconfigured domain controller. The absence of lockout after 47 failures indicates the lockout threshold is not enforced on CORP-DC-01. Priority: isolate DC from the /32 source and audit for any 4624 events from 185.220.101.47 before closing.*

---

## Why the output is accurate

The moat isn't the model — it's the domain knowledge encoded in the system prompt.

**Event ID → MITRE mapping rules.** 4625 with %%2313 (wrong password) maps to T1110.001 Password Guessing, not the generic T1110. 4625 with multiple usernames maps to T1110.003 Password Spraying. lsass.exe as the process on a 4625 event is normal auth behavior — not T1003. These distinctions matter and most AI triage tools get them wrong.

**Failure reason code semantics.** %%2313 means the account exists and the password is wrong — the highest signal for an active credential attack. %%2304 means account restrictions triggered — possible lockout evasion. The prompt decodes these explicitly.

**Enrichment weighting.** AbuseIPDB ≥ 80 raises severity one level minimum and must be cited by name. A confirmed Tor exit node triggers an anonymization note. OTX pulse counts and malware family names are referenced directly in the reasoning.

**Recommendation quality standards.** Each recommendation must reference a specific indicator from the alert (the actual IP, hostname, username, event code) and be executable by a Tier 1–2 analyst without further context. Generic output is rejected at the prompt level.

---

## Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js (App Router) + vanilla CSS |
| API | Next.js API Routes |
| LLM Inference | Groq — Llama 3.3 70B Versatile |
| Threat Intel | AbuseIPDB · VirusTotal · AlienVault OTX |
| Deployment | Vercel |

The architecture is model-agnostic. Swapping Groq for any OpenAI-compatible API or the Anthropic SDK is a one-line change in `app/api/triage/route.js`.

---

## Local setup

**Prerequisites:** Node.js 18+. Free API accounts on Groq, AbuseIPDB, VirusTotal, and AlienVault OTX.

```bash
git clone https://github.com/LuisDuarte0/arbiter
cd arbiter
npm install
```

Create `.env.local` in the project root:

```
GROQ_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
OTX_API_KEY=your_key_here
```

```bash
npm run dev
```

Open `http://localhost:3000`.

---

## Project structure

```
arbiter/
├── app/
│   ├── api/
│   │   └── triage/
│   │       └── route.js        # Core triage engine — enrichment + LLM
│   ├── components/
│   │   ├── Header.js
│   │   ├── AlertQueue.js       # Session history panel
│   │   ├── AnalysisPanel.js    # Alert input + triage output
│   │   └── IntelPanel.js       # Threat intelligence enrichment
│   ├── globals.css
│   ├── layout.js
│   └── page.js
└── .env.local                  # API keys — never committed
```

---

## Roadmap

- [ ] MITRE ATT&CK Navigator heatmap for session coverage visualization
- [ ] Multi-alert batch triage mode
- [ ] KQL/Sigma rule suggestions based on detected technique
- [ ] Export triage reports as PDF
- [ ] Detection gap analysis across a session

---

## Author

**Luis Carlos Moreira Duarte**
Cybersecurity student · CompTIA Security+ · BTL1 

[LinkedIn](https://linkedin.com/in/luis-duarte-560993291) 

---

