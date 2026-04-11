// ── WINDOWS SECURITY EVENT MAPPER ─────────────────────────────────────────────
// Maps Windows Event Log fields to ACS v2.0 provenance-wrapped object.
// Every acs_data field is { value, source } where source is a semantic identifier.
// Fields derived from the same EventID lookup table share source 'derived:event_id_table'
// and are therefore NOT provenance-independent (correct — prevents false signal firing).

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

const w = (value, source) => ({ value: value ?? null, source: (value != null && value !== '') ? source : null })

export function mapWindows(text, parsedFields) {
  const eventId = parsedFields.eventId ?? null

  const eventTypeVal   = eventId ? (EVENT_TYPE_MAP[eventId]    ?? 'unknown') : 'unknown'
  const eventOutcomeVal = eventId ? (EVENT_OUTCOME_MAP[eventId] ?? 'unknown') : 'unknown'
  const actionVal      = eventId ? (EVENT_ACTION_MAP[eventId]   ?? 'unknown') : 'unknown'

  // All three are derived from the same EventID lookup — intentionally shared source
  // so areProvenanceIndependent returns false for any pair of these three fields.
  const DERIVED_SRC = 'derived:event_id_table'

  return {
    meta: {
      vendor_origin: 'windows',
      raw_event_id:  eventId,
    },
    acs_data: {
      timestamp:    w(parsedFields.timestamp,                          'raw:kv:TimeCreated'),
      event_type:   { value: eventTypeVal,    source: eventId ? DERIVED_SRC : null },
      event_outcome:{ value: eventOutcomeVal, source: eventId ? DERIVED_SRC : null },
      action:       { value: actionVal,       source: eventId ? DERIVED_SRC : null },
      user:         w(parsedFields.username,                           'raw:kv:SubjectUserName'),
      src_ip:       w(parsedFields.srcIp ?? parsedFields.ipAddress,   'raw:kv:IpAddress'),
      src_port:     w(null,                                            null),
      dest_ip:      w(null,                                            null),
      dest_port:    w(null,                                            null),
      host:         w(parsedFields.asset,                              'raw:kv:Computer'),
      object_name:  w(parsedFields.objectName,                         'raw:kv:ObjectName'),
      task_name:    w(parsedFields.taskName,                           'raw:kv:TaskName'),
      service_name: w(parsedFields.serviceName,                        'raw:kv:ServiceName'),
      command_line: w(parsedFields.commandLine,                        'raw:kv:CommandLine'),
      process_name: w(parsedFields.processName,                        'raw:kv:NewProcessName'),
      count:        w(parsedFields.count ? parseInt(parsedFields.count, 10) : null, 'raw:kv:Count'),
      logon_type:   w(parsedFields.logonType,                          'raw:kv:LogonType'),
      target_user:  w(parsedFields.targetUsername,                     'raw:kv:TargetUserName'),
    }
  }
}
