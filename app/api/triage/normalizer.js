// ── ACS NORMALIZATION CORE ────────────────────────────────────────────────────
// Merges mapper output, applies defaults, calculates normalization_score.
// This is the single entry point for all log normalization.
// All acs_data fields are { value, source } provenance-wrapped objects.

import { mapWindows }    from './mappers/windows.js'
import { mapLinux }      from './mappers/linux.js'
import { mapCloudTrail } from './mappers/cloudtrail.js'
import { mapGeneric }    from './mappers/generic.js'

// Weighted field scores — must sum to 1.0
// 'resource' is a logical proxy: object_name ?? task_name ?? service_name ?? resource_name
const FIELD_WEIGHTS = {
  event_type:    0.20,
  event_outcome: 0.15,
  action:        0.15,
  src_ip:        0.15,
  user:          0.10,
  timestamp:     0.10,
  host:          0.10,
  resource:      0.05,   // proxy — not a real field; resolved below
}

const NULL_FIELD = { value: null, source: null }

const ACS_DEFAULTS = {
  timestamp:     NULL_FIELD,
  event_type:    { value: 'unknown', source: null },
  event_outcome: { value: 'unknown', source: null },
  action:        { value: 'unknown', source: null },
  user:          NULL_FIELD,
  src_ip:        NULL_FIELD,
  src_port:      NULL_FIELD,
  dest_ip:       NULL_FIELD,
  dest_port:     NULL_FIELD,
  host:          NULL_FIELD,
  object_name:   NULL_FIELD,
  task_name:     NULL_FIELD,
  service_name:  NULL_FIELD,
  resource_name: NULL_FIELD,
  command_line:  NULL_FIELD,
  process_name:  NULL_FIELD,
  count:         NULL_FIELD,
  logon_type:    NULL_FIELD,
  target_user:   NULL_FIELD,
}

function detectVendor(text) {
  // CloudTrail MUST be checked before Windows — CloudTrail JSON contains "eventID" which matches Windows regex
  if (/eventSource.*amazonaws|CloudTrail|"eventName"\s*:|"eventTime"\s*:|"awsRegion"\s*:/i.test(text)) return 'cloudtrail'
  if (/EventCode[=:\s]|Security-Auditing|Microsoft-Windows/i.test(text)) return 'windows'
  if (/sshd\[|auth\.log|sudo:|PAM|kernel\[|Failed password|Accepted (password|publickey)|CRON\[|crond\[|systemd\[|auditd\[|su\[|login\[/i.test(text)) return 'linux'
  return 'unknown'
}

// Reads .value from a provenance-wrapped field — handles both legacy flat values and wrapped objects
function fieldValue(f) {
  if (f === null || f === undefined) return null
  if (typeof f === 'object' && 'value' in f) return f.value
  return f  // legacy flat value fallback
}

function calculateNormalizationScore(acsData) {
  // Resolve the logical 'resource' proxy
  const resourceProxy = fieldValue(acsData.object_name)
    ?? fieldValue(acsData.task_name)
    ?? fieldValue(acsData.service_name)
    ?? fieldValue(acsData.resource_name)
    ?? null

  let score = 0
  for (const [field, weight] of Object.entries(FIELD_WEIGHTS)) {
    if (field === 'resource') {
      if (resourceProxy !== null && resourceProxy !== 'unknown') score += weight
      continue
    }
    const val = fieldValue(acsData[field])
    if (val !== null && val !== undefined && val !== 'unknown') {
      score += weight
    }
  }
  return Math.round(score * 100) / 100
}

function applyDefaults(acsData) {
  return { ...ACS_DEFAULTS, ...acsData }
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
