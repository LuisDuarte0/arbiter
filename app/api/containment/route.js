export const maxDuration = 15

const PLAYBOOK_LOOKUP = {
  ACS_AUTH_FAILURE_LOW: {
    phase1: [
      "Verify whether the authentication failure was from an authorized source by checking the account's recent successful authentication history",
      "Confirm the targeted account is active and the credential configuration is valid — rule out expired passwords or MFA prompts",
      "Check whether the failure was a one-time event or the first in a developing pattern",
    ],
    phase2: [
      "Determine whether the same source appeared in authentication events on other assets in this session",
      "Check whether a successful authentication followed the failure from the same source",
    ],
    phase3_surface_safe: [
      "If failure is confirmed malicious: document the source IP and account targeted before any account action",
      "Verify whether blocking the source IP would affect legitimate users sharing the same egress point",
      "Confirm with the account owner before any credential reset or account disable action",
    ],
  },
  ACS_AUTH_FAILURE_HIGH: {
    phase1: [
      "Verify whether the failure volume is consistent with automated tooling — check timestamps for sub-second intervals",
      "Confirm whether any authentication succeeded during or after the failure sequence from the same source",
      "Check whether account lockout policies activated and whether they functioned as expected",
    ],
    phase2: [
      "Determine the full time window of the failure sequence and correlate with other activity on the same asset",
      "Check whether the source IP appears in authentication events across other assets in this session",
      "Assess whether the targeted accounts share a pattern — same group, same privilege level, or same naming convention",
    ],
    phase3_surface_safe: [
      "If confirmed credential stuffing or brute force: establish the complete list of accounts targeted before any lockout action",
      "Verify the source IP is not shared infrastructure before blocking at perimeter",
      "Confirm the failure sequence has fully stopped before concluding scope",
    ],
  },
  ACS_AUTH_FAILURE_MASS: {
    phase1: [
      "Verify whether any authentication succeeded during the mass failure window — this is the highest-priority question",
      "Determine whether the failure pattern targets a credential list or a single account with many attempts",
      "Confirm whether automated lockout or rate limiting activated during the attack window",
    ],
    phase2: [
      "Identify every account that received a failure attempt and whether any shows subsequent successful authentication",
      "Determine whether the attack originated from a single source or a distributed set of IPs",
    ],
    phase3_surface_safe: [
      "If any account shows success following the failure sequence: prioritize that account for immediate investigation before any broad action",
      "Establish the complete affected account list before any mass lockout or reset action",
      "Coordinate with identity team before any account management action at this scale",
    ],
  },
  ACS_PRIVILEGE_ACTION: {
    phase1: [
      "Verify whether the privilege action was authorized and expected for this account at this time",
      "Check whether the action was preceded by unusual authentication or access patterns from the same identity",
      "Confirm the action type against known administrative workflows — was a change window open?",
    ],
    phase2: [
      "Determine whether other privilege actions occurred from the same identity in the same session",
      "Check whether the privilege change affected accounts or groups with elevated access",
    ],
    phase3_surface_safe: [
      "If confirmed unauthorized: document the exact privilege change made before any reversal action",
      "Verify the current state of the affected account or group before taking corrective action",
      "Confirm with system owner that reverting the privilege change will not break dependent services",
    ],
  },
  ACS_CLOUD_PRIVILEGE_ESCALATION: {
    phase1: [
      "Verify whether the IAM policy attachment was authorized and matches expected provisioning activity",
      "Check the current effective permissions of the target account — confirm what access was actually granted",
      "Confirm with the IAM team or system owner whether this attachment was part of a planned change",
    ],
    phase2: [
      "Review all IAM changes in the same time window from the same source identity",
      "Determine whether the attached policy has been invoked since attachment",
      "Assess whether the source identity has made other IAM changes in this session",
    ],
    phase3_surface_safe: [
      "If confirmed unauthorized: document the policy ARN and target account before any detachment action",
      "Verify whether the target account was used with the escalated permissions before taking action",
      "Confirm that detaching the policy will not affect legitimate dependent processes before proceeding",
    ],
  },
  ACS_CLOUD_PRIVILEGE_ESCALATION_ATTEMPT: {
    phase1: [
      "Verify whether the blocked policy attachment was an authorized attempt that failed due to misconfigured permissions",
      "Check whether the source identity attempted other IAM operations before or after this blocked attempt",
      "Determine whether the source identity has legitimate administrative responsibilities",
    ],
    phase2: [
      "Assess the pattern of IAM API calls from this identity in the session — was this isolated or part of a sequence?",
      "Determine whether the source IP correlates with other API activity across different AWS services",
    ],
    phase3_surface_safe: [
      "If confirmed adversarial probing: document all IAM API calls from this identity before any access revocation",
      "Verify the source identity's legitimate access scope before any credential action",
      "Confirm with AWS account owner before any IAM identity suspension",
    ],
  },
  ACS_CLOUD_ROLE_ASSUMPTION_FAIL: {
    phase1: [
      "Verify whether the failed role assumption was an authorized attempt blocked by a misconfigured trust policy",
      "Check whether the failure was followed by a successful assumption through a different path or role",
      "Confirm whether the source identity has legitimate reason to assume this role",
    ],
    phase2: [
      "Determine whether other role assumption attempts occurred from the same source in this session",
      "Check whether the targeted role has been successfully assumed by other identities recently",
    ],
    phase3_surface_safe: [
      "If confirmed adversarial: document all STS API calls from this identity before any access action",
      "Verify the trust policy of the targeted role to understand what access was being sought",
    ],
  },
  ACS_REMOTE_DOWNLOAD: {
    phase1: [
      "Verify whether the remote resource contacted is known infrastructure or an unexpected external destination",
      "Check whether any files were written to disk following the download command",
      "Confirm whether the process that executed the download is expected to make external network connections",
    ],
    phase2: [
      "Determine whether the destination IP or domain appears in other network connections from this asset",
      "Check whether the downloaded content was subsequently executed on the host",
    ],
    phase3_surface_safe: [
      "If confirmed malicious download: establish what was downloaded and whether it executed before any host action",
      "Verify the current state of the affected host — running processes, new files, scheduled tasks — before isolation",
      "Preserve volatile evidence before any containment action that could overwrite it",
    ],
  },
  ACS_BASE64_EXECUTION: {
    phase1: [
      "Verify whether encoded execution is expected or authorized in this environment — rule out legitimate automation",
      "Decode the base64 content and assess what the command does before drawing conclusions",
      "Check whether the execution produced any child processes, network connections, or file writes",
    ],
    phase2: [
      "Determine whether other encoded execution events occurred on this or other assets in the session",
      "Check whether the decoded command contacts external infrastructure or writes to persistent storage",
    ],
    phase3_surface_safe: [
      "If confirmed malicious: document the decoded command content before any process termination",
      "Establish what the command achieved before any host containment action",
      "Preserve the process tree and network state before isolation",
    ],
  },
  ACS_SUDO_SHELL: {
    phase1: [
      "Verify whether the interactive shell escalation was authorized for this account on this host",
      "Check what commands were executed within the escalated shell session",
      "Confirm whether the account that invoked sudo has a legitimate administrative role on this system",
    ],
    phase2: [
      "Determine whether other privilege escalation events occurred on this host in the same session",
      "Check whether the escalated shell session made network connections or wrote files",
    ],
    phase3_surface_safe: [
      "If confirmed unauthorized escalation: document all commands executed in the sudo session before any account action",
      "Check for persistence mechanisms installed during the escalated session before containment",
      "Verify the current privilege state of the account before any credential action",
    ],
  },
  ACS_SUSPICIOUS_DATA_ACCESS: {
    phase1: [
      "Verify whether access to this resource was within the expected scope for this identity",
      "Check whether the access was read-only or included write, delete, or copy operations",
      "Confirm whether this identity has a legitimate business need for this specific resource",
    ],
    phase2: [
      "Determine the volume and pattern of access — was this a single read or a sustained data collection?",
      "Check whether the accessed data was exfiltrated or remained within the environment",
    ],
    phase3_surface_safe: [
      "If confirmed unauthorized access: document the complete list of resources accessed before any identity action",
      "Determine whether data left the environment before any containment action",
      "Coordinate with data owner before any access revocation that could affect legitimate operations",
    ],
  },
  AUDIT_LOG_CLEARED: {
    phase1: [
      "Verify whether the log clearing was authorized and part of a documented maintenance procedure",
      "Check what activity occurred on this host immediately before the clearing — this is what was intentionally removed",
      "Confirm with the system owner whether a maintenance window was open at the time of clearing",
    ],
    phase2: [
      "Check other hosts in the environment for similar log clearing events in the same time window",
      "Examine forwarded log copies in your SIEM or log aggregator for the period before clearing",
    ],
    phase3_surface_safe: [
      "If confirmed malicious: the pre-clearing activity is the primary unknown — establish what can be recovered from forwarded logs before any host action",
      "Document the timeline gap created by the clearing before any remediation",
      "Preserve the current host state before any action that could overwrite remaining forensic evidence",
    ],
  },
  ACCOUNT_CREATED_SUSPICIOUS: {
    phase1: [
      "Verify whether the new account name matches any legitimate provisioning patterns or naming conventions",
      "Check whether the creating identity had authorization for user management on this system",
      "Confirm whether the account creation was logged in any identity management system or ticketing system",
    ],
    phase2: [
      "Check whether the new account has been used since creation — any authentication or privilege activity",
      "Determine whether the new account was added to any groups or granted permissions after creation",
    ],
    phase3_surface_safe: [
      "If confirmed unauthorized: document the account's current state — groups, permissions, last logon — before any disable action",
      "Check for any resources or sessions owned by this account before deletion",
      "Confirm with identity team before any account removal action",
    ],
  },
  LSASS_DUMP_RUNDLL32: {
    phase1: [
      "Verify whether the comsvcs MiniDump invocation was part of an authorized diagnostic or security testing procedure",
      "Check whether any dump files were written to disk and whether they persist at the output path",
      "Confirm whether the process that invoked rundll32 was an authorized administrative tool",
    ],
    phase2: [
      "Determine whether any lateral movement or new authentication events occurred after the dump",
      "Check whether the dump file was accessed, compressed, or transferred after creation",
    ],
    phase3_surface_safe: [
      "If confirmed credential dump: assume credentials for all accounts loaded in LSASS are compromised — document scope before any credential action",
      "Establish whether the dump file was exfiltrated before any host containment",
      "Coordinate credential reset scope with identity team — this may require broad credential rotation",
    ],
  },
  ACS_MALICIOUS_SOURCE_AUTH_SUCCESS: {
    phase1: [
      "Verify whether the successful authentication represents a legitimate access or a compromised credential — this is the highest-priority question",
      "Check all actions taken by this identity after the successful authentication in this session",
      "Correlate this success with the prior failure sequence from the same source to establish the complete attack timeline",
    ],
    phase2: [
      "Determine the full scope of what the authenticated identity accessed after the successful logon",
      "Check whether the authenticated session established persistence, moved laterally, or accessed sensitive resources",
    ],
    phase3_surface_safe: [
      "If confirmed compromise: document all activity by the authenticated identity before any session termination",
      "Establish whether persistence was installed during the authenticated session before host isolation",
      "Coordinate credential invalidation with identity team — the compromised credential may be used elsewhere",
    ],
  },
  POWERSHELL_ENCODED: {
    phase1: [
      "Verify whether encoded PowerShell execution is expected or authorized in this environment",
      "Decode the base64 command and assess what it does — note any network connections, file writes, or process spawning",
      "Check whether the execution produced child processes or network connections following the encoded command",
    ],
    phase2: [
      "Determine whether other PowerShell execution events occurred on this host in the session",
      "Check whether the decoded command contacted external infrastructure",
    ],
    phase3_surface_safe: [
      "If confirmed malicious: document the decoded command content and its effects before any process action",
      "Establish what the command achieved — downloads, persistence, lateral movement — before host isolation",
      "Preserve the PowerShell event log before any log clearing or host action",
    ],
  },
  LOGON_FAILURE_LOW: {
    phase1: [
      "Verify whether the failure was isolated or the beginning of a broader pattern",
      "Check whether the account targeted is active and the credential configuration is valid",
      "Confirm the asset context — a single failure on a domain controller carries different weight than on a workstation",
    ],
    phase2: [
      "Check whether this indicator has appeared previously in this session across other assets",
      "Determine whether the same account shows successful authentication from unusual sources",
    ],
    phase3_surface_safe: [
      "If confirmed malicious and part of a pattern: document the account and source before any action",
      "Verify with the account owner before any credential reset",
    ],
  },
}

const GENERIC_PLAYBOOK = {
  phase1: [
    "Verify whether the detected activity was authorized and expected for this identity and asset",
    "Check the context surrounding the event — what preceded it and what followed",
    "Confirm the verdict against raw log data before drawing any conclusions",
  ],
  phase2: [
    "Determine whether similar activity occurred on other assets in this session",
    "Assess the scope of the detected behavior before considering any response action",
  ],
  phase3_surface_safe: [
    "If confirmed malicious: document the complete activity scope before any containment action",
    "Preserve forensic evidence in its current state before any host or identity action",
    "Coordinate with the system owner before any action that could affect legitimate operations",
  ],
}

function buildPlaybook(triage, signals) {
  const dominantRule = signals?.find(s =>
    s.signal_layer === 'behavioral' && !s.frequency
  )?.rule ?? signals?.find(s =>
    s.signal_layer === 'enrichment' && s.category === 'behavioral'
  )?.rule ?? signals?.find(s =>
    s.signal_layer === 'temporal' && !s.frequency
  )?.rule

  const entry = PLAYBOOK_LOOKUP[dominantRule] ?? GENERIC_PLAYBOOK

  const phase1Steps = [...entry.phase1]
  const phase2Steps = [...entry.phase2]

  const hasCampaign    = signals?.some(s => s.rule === 'CORRELATED_INDICATOR_ACTIVITY')
  const hasRepeated    = signals?.some(s => s.rule === 'REPEATED_INDICATOR')
  const hasMaliciousIP = signals?.some(s => s.rule === 'ENRICHMENT_CONFIRMED_MALICIOUS')
  const hasAuthSuccess = signals?.some(s => s.rule === 'ACS_MALICIOUS_SOURCE_AUTH_SUCCESS')

  if (hasCampaign) {
    phase2Steps.push(
      "This indicator has appeared across multiple assets in this session — scope investigation to all affected assets before containing any single one"
    )
  }
  if (hasRepeated && !hasCampaign) {
    phase2Steps.push(
      "This indicator has recurred in this session — determine the full recurrence pattern before concluding scope"
    )
  }
  if (hasMaliciousIP) {
    phase2Steps.push(
      "The source IP is confirmed malicious across external threat intelligence — check whether this IP appears in logs outside this session"
    )
  }
  if (hasAuthSuccess) {
    phase2Steps.push(
      "A successful authentication from this source followed prior failures — the scope has expanded beyond probing to active access"
    )
  }

  const isTraceRequired = triage.verdict_reliability_class !== 'SURFACE_SAFE'

  const phase3 = isTraceRequired
    ? {
        blocked: true,
        blocked_reason:
          "This verdict is classified TRACE_REQUIRED — the engine identified insufficient certainty for immediate containment. " +
          "Complete Phase 1 verification and confirm a true positive before considering any containment action. " +
          "Premature containment on an unconfirmed verdict may disrupt legitimate operations.",
        steps: [],
      }
    : {
        blocked: false,
        blocked_reason: null,
        steps: entry.phase3_surface_safe ?? GENERIC_PLAYBOOK.phase3_surface_safe,
      }

  return {
    phase1: {
      label: 'PHASE 1 — VERIFY THE VERDICT',
      note: 'Complete all steps before proceeding. These establish whether the verdict is a true positive.',
      steps: phase1Steps,
    },
    phase2: {
      label: 'PHASE 2 — SCOPE THE INCIDENT',
      note: 'If Phase 1 confirms a true positive: determine the full scope before any containment action.',
      steps: phase2Steps,
      enabled: phase2Steps.length > 0,
    },
    phase3: {
      label: 'PHASE 3 — CONTAINMENT PREREQUISITES',
      ...phase3,
    },
    meta: {
      vendor: triage.vendor_origin ?? 'unknown',
      verdict_class: triage.verdict_class,
      verdict_reliability_class: triage.verdict_reliability_class,
      dominant_signal: dominantRule ?? 'unknown',
      signal_count: signals?.length ?? 0,
    },
  }
}

export async function POST(request) {
  try {
    const { triage, enrichment, ips, signals } = await request.json()

    if (!triage) {
      return Response.json({ error: 'No triage data provided.' }, { status: 400 })
    }

    const playbook = buildPlaybook(triage, signals ?? [])
    return Response.json({ playbook })

  } catch (err) {
    console.error('[ARBITER] Containment error:', err)
    return Response.json({
      error: err.message ?? 'Playbook generation failed.'
    }, { status: 500 })
  }
}
