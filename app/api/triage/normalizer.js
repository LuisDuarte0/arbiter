// ── ACS NORMALIZATION CORE ────────────────────────────────────────────────────
// Merges mapper output, applies defaults, calculates normalization_score.
// This is the single entry point for all log normalization.

import { mapWindows }    from './mappers/windows.js'
import { mapLinux }      from './mappers/linux.js'
import { mapCloudTrail } from './mappers/cloudtrail.js'
import { mapGeneric }    from './mappers/generic.js'

// Weighted field scores — must sum to 1.0
const FIELD_WEIGHTS = {
  event_type:    0.20,
  event_outcome: 0.15,
  action:        0.15,
  src_ip:        0.15,
  user:          0.10,
  timestamp:     0.10,
  host:          0.10,
  resource:      0.05,
}

function detectVendor(text) {
  // CloudTrail MUST be checked before Windows — CloudTrail JSON contains "eventID" which matches Windows regex
  if (/eventSource.*amazonaws|CloudTrail|"eventName"\s*:|"eventTime"\s*:|"awsRegion"\s*:/i.test(text)) return 'cloudtrail'
  if (/EventCode[=:\s]|Security-Auditing|Microsoft-Windows/i.test(text)) return 'windows'
  if (/sshd\[|auth\.log|sudo:|PAM|kernel\[|Failed password|Accepted (password|publickey)|CRON\[|crond\[|systemd\[|auditd\[|su\[|login\[/i.test(text)) return 'linux'
  return 'unknown'
}

function calculateNormalizationScore(acsData) {
  let score = 0
  for (const [field, weight] of Object.entries(FIELD_WEIGHTS)) {
    const val = acsData[field]
    if (val !== null && val !== undefined && val !== 'unknown') {
      score += weight
    }
  }
  return Math.round(score * 100) / 100
}

function applyDefaults(acsData) {
  const defaults = {
    timestamp: null, event_type: 'unknown', event_outcome: 'unknown',
    action: 'unknown', user: null, src_ip: null, src_port: null,
    dest_ip: null, dest_port: null, host: null, resource: null,
    command_line: null,
  }
  return { ...defaults, ...acsData }
}

export function normalize(text, parsedFields = {}) {
  const vendor = detectVendor(text)

  let partial = null
  let isGeneric = false

  switch (vendor) {
    case 'windows':
      partial = mapWindows(text, parsedFields)
      break
    case 'cloudtrail':
      partial = mapCloudTrail(text)
      break
    case 'linux':
      partial = mapLinux(text)
      break
    default:
      partial = mapGeneric(text)
      isGeneric = true
  }

  if (!partial) {
    partial = mapGeneric(text)
    isGeneric = true
  }

  const acsData = applyDefaults(partial.acs_data ?? {})
  const normalizationScore = calculateNormalizationScore(acsData)

  return {
    meta: {
      normalization_score: normalizationScore,
      is_generic:          isGeneric || (partial.meta?.is_generic ?? false),
      vendor_origin:       partial.meta?.vendor_origin ?? 'unknown',
      raw_event_id:        partial.meta?.raw_event_id ?? null,
    },
    acs_data: acsData,
  }
}
