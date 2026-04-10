// ── WINDOWS SECURITY EVENT MAPPER ─────────────────────────────────────────────
// Maps Windows Event Log fields to ACS v1.0 partial object.
// Never reads directly from detection engine — returns normalized fields only.

const EVENT_TYPE_MAP = {
  '4624': 'auth',    '4625': 'auth',    '4648': 'auth',    '4771': 'auth',
  '4688': 'process', '4689': 'process',
  '4698': 'process', '4702': 'process', '4699': 'process', '4700': 'process',
  '4697': 'process', '7045': 'process',
  '4663': 'privilege', '4656': 'privilege', '4670': 'privilege',
  '4720': 'privilege', '4732': 'privilege', '4728': 'privilege',
  '1102': 'privilege', '4719': 'privilege',
  '4104': 'process',
}

const EVENT_OUTCOME_MAP = {
  '4624': 'success', '4625': 'failure', '4648': 'success', '4771': 'failure',
  '4688': 'success', '4663': 'success', '4656': 'success',
  '4698': 'success', '4720': 'success', '4732': 'success',
  '1102': 'success', '4719': 'success',
}

const EVENT_ACTION_MAP = {
  '4624': 'logon',                  '4625': 'logon_failed',
  '4648': 'logon_explicit',         '4771': 'kerberos_preauth_failed',
  '4688': 'process_created',        '4689': 'process_terminated',
  '4698': 'scheduled_task_created', '4702': 'scheduled_task_modified',
  '4697': 'service_installed',      '7045': 'service_installed',
  '4663': 'object_access',          '4656': 'object_access_requested',
  '4720': 'account_created',        '4732': 'account_added_to_group',
  '1102': 'audit_log_cleared',      '4719': 'audit_policy_changed',
  '4104': 'script_block_logged',
}

export function mapWindows(text, parsedFields) {
  const eventId = parsedFields.eventId ?? null

  const partial = {
    meta: {
      vendor_origin: 'windows',
      raw_event_id:  eventId,
    },
    acs_data: {
      timestamp:    parsedFields.timestamp ?? null,
      event_type:   eventId ? (EVENT_TYPE_MAP[eventId] ?? 'unknown') : 'unknown',
      event_outcome: eventId ? (EVENT_OUTCOME_MAP[eventId] ?? 'unknown') : 'unknown',
      action:       eventId ? (EVENT_ACTION_MAP[eventId] ?? 'unknown') : 'unknown',
      user:         parsedFields.username ?? null,
      src_ip:       parsedFields.srcIp ?? parsedFields.ipAddress ?? null,
      src_port:     null,
      dest_ip:      null,
      dest_port:    null,
      host:         parsedFields.asset ?? null,
      resource:     parsedFields.objectName ?? parsedFields.taskName ?? parsedFields.serviceName ?? null,
      command_line: parsedFields.commandLine ?? null,
      parent_process: parsedFields.parentProcess ?? null,
      process_name:   parsedFields.processName ?? null,
      count:          parsedFields.count ? parseInt(parsedFields.count, 10) : null,
      object_name:    parsedFields.objectName ?? null,
      logon_type:     parsedFields.logonType ?? null,
      target_user:    parsedFields.targetUsername ?? null,
      task_content:   parsedFields.taskContent ?? null,
    }
  }

  return partial
}
