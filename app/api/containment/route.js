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
  NTDS_ACCESS: {
    phase1: [
      "Verify whether access to the NTDS database was expected for this account and process",
      "Check whether the accessing process is a known legitimate tool or an unexpected binary",
      "Confirm with the domain admin team whether any authorized AD replication or backup was scheduled",
    ],
    phase2: [
      "Determine whether the NTDS file was copied or transferred after access",
      "Check for other credential access indicators on the same DC in this session",
      "Assess whether any new authentication events occurred from unusual sources after this access",
    ],
    phase3_surface_safe: [
      "If confirmed unauthorized: assume all domain credentials are compromised — document scope before any action",
      "Establish whether the NTDS file was exfiltrated before any containment action",
      "Coordinate with identity team — full domain credential rotation may be required",
    ],
  },
  SAM_ACCESS: {
    phase1: [
      "Verify whether access to the SAM database was expected for this account and process",
      "Check whether the accessing process matches known legitimate tools",
      "Confirm whether any authorized credential backup or migration was scheduled",
    ],
    phase2: [
      "Determine whether the SAM file was copied or read in full",
      "Check for other credential access indicators on the same host in this session",
      "Assess whether any new authentication events occurred from unusual sources after this access",
    ],
    phase3_surface_safe: [
      "If confirmed unauthorized: assume local account credentials are compromised",
      "Establish whether the SAM content was exfiltrated before any containment action",
      "Coordinate credential reset for all local accounts on this host",
    ],
  },
  MIMIKATZ_DETECTED: {
    phase1: [
      "Verify whether the process invoking credential access patterns was expected on this host",
      "Check whether the binary name is a known legitimate tool renamed to evade detection",
      "Confirm whether any authorized penetration test or red team exercise is active",
    ],
    phase2: [
      "Determine whether any lateral movement or new authentication events occurred after execution",
      "Check whether the process made network connections or wrote credential data to disk",
    ],
    phase3_surface_safe: [
      "If confirmed malicious: assume all credentials cached on this host are compromised",
      "Check for persistence mechanisms installed during or after the credential dump",
      "Coordinate broad credential rotation with identity team before any host isolation",
    ],
  },
  ACS_LATERAL_MOVEMENT_CANDIDATE: {
    phase1: [
      "Verify whether the source and destination hosts share an expected trust relationship",
      "Check whether the credential used is consistent with normal access patterns for this account",
      "Confirm whether the logon type and source IP match expected administrative or service behavior",
    ],
    phase2: [
      "Determine what actions were taken on the destination host after the successful logon",
      "Check whether the same credential was used for other lateral connections in this session",
      "Assess whether the source host shows signs of compromise that would explain the movement",
    ],
    phase3_surface_safe: [
      "If confirmed lateral movement: establish the full traversal path before isolating any single host",
      "Document all hosts reached via this credential before any credential invalidation",
      "Coordinate containment scope with the incident response team — single-host isolation may be insufficient",
    ],
  },
  ACS_HIGH_VOLUME_DATA_ACCESS: {
    phase1: [
      "Verify whether the access volume is consistent with legitimate activity for this account",
      "Check whether the accessed resources were within the expected scope for this identity",
      "Confirm whether any authorized data migration or backup process was running",
    ],
    phase2: [
      "Determine whether the data accessed was exfiltrated or remained within the environment",
      "Assess the total volume of data accessed across the session",
      "Check whether the access pattern suggests automated tooling or manual browsing",
    ],
    phase3_surface_safe: [
      "If confirmed unauthorized: document the complete list of resources accessed before any identity action",
      "Determine data classification of accessed resources before escalating",
      "Coordinate with data owner and legal team before any containment action involving sensitive data",
    ],
  },
  ACS_ACCOUNT_DELETION: {
    phase1: [
      "Verify whether the account deletion was authorized and matches expected lifecycle activity",
      "Check whether the deleted account had active sessions or elevated permissions at time of deletion",
      "Confirm whether the deletion was logged in any identity management or ticketing system",
    ],
    phase2: [
      "Determine whether the deleted account was used for any malicious activity before deletion",
      "Check whether other account management actions occurred from the same principal in this session",
    ],
    phase3_surface_safe: [
      "If confirmed malicious: check whether account deletion was intended to destroy evidence — recover from directory tombstone if possible",
      "Document the deleted account's group memberships and permissions from backup before any recovery action",
      "Assess whether other accounts created by the same principal should be reviewed",
    ],
  },
  SERVICE_SUSPICIOUS_PATH: {
    phase1: [
      "Verify whether the service binary path resolves to a legitimate executable",
      "Check the service creation context — which account created it and when",
      "Confirm whether any authorized software deployment or update was running at the time",
    ],
    phase2: [
      "Determine whether the service binary was executed after installation",
      "Check whether the service binary was written to disk from a network source",
      "Assess whether other suspicious service installations occurred in this session",
    ],
    phase3_surface_safe: [
      "If confirmed malicious: document the service binary hash and path before any removal",
      "Check for persistence mechanisms linked to this service before stopping it",
      "Verify the service is not a dependency for legitimate processes before disabling",
    ],
  },
  LOLBIN_MSHTA_REMOTE: {
    phase1: [
      "Verify whether the remote resource contacted by mshta is known or expected infrastructure",
      "Check whether mshta spawned any child processes following the remote connection",
      "Confirm whether mshta is expected to make external connections in this environment",
    ],
    phase2: [
      "Determine whether the remote resource delivered a payload that was subsequently executed",
      "Check for any persistence mechanisms installed after the mshta execution",
    ],
    phase3_surface_safe: [
      "If confirmed malicious: establish what was delivered and executed before any host action",
      "Check for child processes spawned by mshta before terminating anything",
      "Preserve the network connection artifacts before host isolation",
    ],
  },
  LOLBIN_CERTUTIL_DOWNLOAD: {
    phase1: [
      "Verify whether certutil was invoked for a legitimate certificate operation or as a download proxy",
      "Check whether any files were written to disk as a result of the certutil execution",
      "Confirm whether certutil network access is expected in this environment",
    ],
    phase2: [
      "Determine whether the downloaded file was subsequently executed",
      "Check for other certutil invocations in the same session",
    ],
    phase3_surface_safe: [
      "If confirmed malicious download: hash and document the downloaded file before any removal",
      "Check for execution of the downloaded payload before host isolation",
      "Preserve the downloaded file as forensic evidence before remediation",
    ],
  },
  LOLBIN_CERTUTIL_SUSPICIOUS_PATH: {
    phase1: [
      "Verify whether the file written to the suspicious path was subsequently executed",
      "Check the file written for indicators of staged payloads or known malicious content",
      "Confirm whether certutil decode operations are expected in this environment",
    ],
    phase2: [
      "Determine whether other files were staged to suspicious paths in this session",
      "Check for execution events originating from the suspicious path directory",
    ],
    phase3_surface_safe: [
      "If confirmed staging: document and hash the staged file before removal",
      "Check for execution of the staged payload before any directory cleanup",
      "Assess whether the staging path contains other artifacts from this session",
    ],
  },
  OFFICE_MACRO_DROPPER: {
    phase1: [
      "Verify whether the Office application that spawned the process was handling a document from an external or untrusted source",
      "Identify the spawned process and its full command line — determine whether it made network connections, wrote files, or spawned further children",
      "Check whether macro execution is expected or authorized for this user and host",
    ],
    phase2: [
      "Determine whether the spawned process persisted — check scheduled tasks, services, and registry run keys on the affected host",
      "Identify all child processes spawned from the LOLBin and trace the full execution chain",
      "Check whether the same document or macro was opened on other hosts in this session",
    ],
    phase3_surface_safe: [
      "Establish the full execution chain from document open to final payload before any host action",
      "Preserve the originating document and all spawned process artifacts before isolation",
      "Document all network connections made by the execution chain — C2 infrastructure must be identified before host isolation",
    ],
  },
  BROWSER_SPAWN_SCRIPTING: {
    phase1: [
      "Verify whether the browser spawning the scripting process is consistent with known enterprise tooling or security agent behavior on this host",
      "Identify the spawned process and its full command line — determine what it attempted to execute or contact",
      "Check whether the user was interacting with the browser at the time or whether this was a background/headless execution",
    ],
    phase2: [
      "Determine whether the spawned process made network connections or wrote files to disk",
      "Check for other anomalous browser activity on this host in the session — unusual URLs, downloads, or browser extension changes",
      "Assess whether the same spawning pattern appeared on other hosts",
    ],
    phase3_surface_safe: [
      "If confirmed malicious: identify the originating URL or browser extension before any host action",
      "Preserve browser history, cache, and extension state as forensic artifacts",
      "Document all child process activity before host isolation — the full execution chain must be understood first",
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

function buildPlaybook(triage, signals, decision_trace = []) {
  // Check decision_trace for enrichment_specific classification
  // When classification came from a specific enrichment signal
  // (e.g. AUDIT_LOG_CLEARED, NTDS_ACCESS, SAM_ACCESS), prefer
  // that signal's playbook entry over the behavioral dominant.
  const classificationTrace = decision_trace?.find(
    e => e.type === 'classification' && e.reason === 'enrichment_specific'
  )
  const classificationRule = classificationTrace?.rule ?? null

  const behavioralDominant = signals?.find(s =>
    s.signal_layer === 'behavioral' && !s.frequency
  )?.rule

  const enrichmentDominant = signals?.find(s =>
    s.signal_layer === 'enrichment' && s.category === 'behavioral'
  )?.rule

  const temporalDominant = signals?.find(s =>
    s.signal_layer === 'temporal' && !s.frequency
  )?.rule

  // Priority: classification source (when enrichment_specific) →
  // behavioral dominant → enrichment behavioral → temporal
  // This ensures AUDIT_LOG_CLEARED, NTDS_ACCESS etc. drive the
  // playbook even when ACS_PRIVILEGE_ACTION is behavioral dominant
  const dominantRule = (classificationRule && PLAYBOOK_LOOKUP[classificationRule])
    ? classificationRule
    : (behavioralDominant && PLAYBOOK_LOOKUP[behavioralDominant])
    ? behavioralDominant
    : (enrichmentDominant && PLAYBOOK_LOOKUP[enrichmentDominant])
    ? enrichmentDominant
    : temporalDominant
    ?? null

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
    const { triage, enrichment, ips, signals, decision_trace } = await request.json()

    if (!triage) {
      return Response.json({ error: 'No triage data provided.' }, { status: 400 })
    }

    const playbook = buildPlaybook(triage, signals ?? [], decision_trace ?? [])
    return Response.json({ playbook })

  } catch (err) {
    console.error('[ARBITER] Containment error:', err)
    return Response.json({
      error: err.message ?? 'Playbook generation failed.'
    }, { status: 500 })
  }
}
