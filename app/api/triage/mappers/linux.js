// ── LINUX AUTH.LOG / SYSLOG MAPPER ────────────────────────────────────────────
// Maps syslog-format text to ACS v2.0 provenance-wrapped object.
// Source format: 'raw:syslog:<segment>:<semantic_source>'
//   segment = 'header' (timestamp / hostname / process extracted from syslog prefix)
//           = 'message' (content after the process[pid]: portion)
// action is independently sourced from event_type — action is a direct text pattern
// match ('raw:syslog:message:action_verb') while event_type is derived from action
// classification ('derived:action_classification') — different sources → independent.

const w = (value, source) => ({ value: value ?? null, source: (value != null && value !== '') ? source : null })

export function mapLinux(text) {
  const get = (pattern) => text.match(pattern)?.[1]?.trim() ?? null

  const actionVal = (() => {
    if (/CRON\[/i.test(text) && /CMD/i.test(text)) return 'command_executed'
    if (/sudo:/i.test(text) && /COMMAND=/i.test(text)) return 'command_executed'
    if (/Failed password/i.test(text)) return 'logon_failed'
    if (/Accepted password|Accepted publickey/i.test(text)) return 'logon'
    if (/sudo:/i.test(text)) return 'privilege_escalation'
    if (/useradd|adduser/i.test(text)) return 'account_created'
    if (/COMMAND=/i.test(text)) return 'command_executed'
    if (/session opened/i.test(text)) return 'session_opened'
    if (/session closed/i.test(text)) return 'session_closed'
    return 'unknown'
  })()

  const eventOutcomeVal = (() => {
    if (/Failed|Invalid|error|refused/i.test(text)) return 'failure'
    if (/Accepted|opened|success/i.test(text)) return 'success'
    return 'unknown'
  })()

  const eventTypeVal = (() => {
    if (['logon_failed','logon','session_opened','session_closed'].includes(actionVal)) return 'auth'
    if (['privilege_escalation','account_created'].includes(actionVal)) return 'privilege'
    if (['command_executed'].includes(actionVal)) return 'process'
    return 'unknown'
  })()

  const userVal = (() => {
    const cronUser = text.match(/CRON\[\d+\]:\s*\((\S+)\)/)?.[1]
    const sudoUser = text.match(/^\S+\s+\S+\s+\S+:\s+(\S+)\s*:/m)?.[1]
    const sshUser  = get(/(?:for invalid user|for user|by)\s+(\S+)/i)
    const genericUser = get(/(?:user|USER)[=:\s]+(\S+)/i)
    return cronUser ?? sudoUser ?? sshUser ?? genericUser ?? null
  })()

  const cmdLineVal = (() => {
    const sudoCmd    = get(/COMMAND=(.+)$/m)
    const cronCmd    = get(/CMD\s+\((.+)\)$/m)
    const genericCmd = get(/CMD=(.+)$/m)
    return sudoCmd ?? cronCmd ?? genericCmd ?? null
  })()

  const srcPortRaw = get(/port\s+(\d+)/i)
  const srcPortVal = srcPortRaw ? parseInt(srcPortRaw, 10) : null

  const failureMatches = text.match(/Failed password|authentication failure|Invalid user|FAILED LOGIN/gi)
  const countVal = failureMatches ? failureMatches.length : null

  return {
    meta: {
      vendor_origin: 'linux',
      raw_event_id:  null,
    },
    acs_data: {
      timestamp:    w(get(/(\w{3}\s+\d+\s+[\d:]+)/),                          'raw:syslog:header:timestamp'),
      event_type:   { value: eventTypeVal,    source: eventTypeVal    !== 'unknown' ? 'derived:action_classification' : null },
      event_outcome:{ value: eventOutcomeVal, source: eventOutcomeVal !== 'unknown' ? 'derived:text_pattern:outcome'  : null },
      action:       { value: actionVal,       source: actionVal       !== 'unknown' ? 'raw:syslog:message:action_verb': null },
      user:         w(userVal,                                                  'raw:syslog:message:username'),
      src_ip:       w(get(/from\s+([\d.]+)/i),                                 'raw:syslog:message:src_ip'),
      src_port:     w(srcPortVal,                                               'raw:syslog:message:src_port'),
      dest_ip:      w(null,                                                     null),
      dest_port:    w(null,                                                     null),
      host:         w(get(/^\w{3}\s+\d+\s+[\d:]+\s+(\S+)\s+/),                'raw:syslog:header:hostname'),
      object_name:  w(null,                                                     null),
      task_name:    w(null,                                                     null),
      service_name: w(null,                                                     null),
      command_line: w(cmdLineVal,                                               'raw:syslog:message:command_line'),
      process_name: w(get(/^\w+\s+\S+\s+(\S+)\[/),                            'raw:syslog:header:process_name'),
      count:        w(countVal,                                                 'derived:text_pattern:failure_count'),
      logon_type:   w(null,                                                     null),
      target_user:  w(null,                                                     null),
    }
  }
}
