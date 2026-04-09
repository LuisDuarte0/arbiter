// ── LINUX AUTH.LOG / SYSLOG MAPPER ────────────────────────────────────────────

export function mapLinux(text) {
  const get = (pattern) => text.match(pattern)?.[1]?.trim() ?? null

  const action = (() => {
    if (/Failed password/i.test(text)) return 'logon_failed'
    if (/Accepted password|Accepted publickey/i.test(text)) return 'logon'
    if (/sudo:/i.test(text)) return 'privilege_escalation'
    if (/useradd|adduser/i.test(text)) return 'account_created'
    if (/COMMAND=/i.test(text)) return 'command_executed'
    if (/session opened/i.test(text)) return 'session_opened'
    if (/session closed/i.test(text)) return 'session_closed'
    return 'unknown'
  })()

  const event_outcome = (() => {
    if (/Failed|Invalid|error|refused/i.test(text)) return 'failure'
    if (/Accepted|opened|success/i.test(text)) return 'success'
    return 'unknown'
  })()

  const event_type = (() => {
    if (['logon_failed','logon','session_opened','session_closed'].includes(action)) return 'auth'
    if (['privilege_escalation','account_created'].includes(action)) return 'privilege'
    if (['command_executed'].includes(action)) return 'process'
    return 'unknown'
  })()

  return {
    meta: {
      vendor_origin: 'linux',
      raw_event_id:  null,
    },
    acs_data: {
      timestamp:    get(/(\w{3}\s+\d+\s+[\d:]+)/),
      event_type,
      event_outcome,
      action,
      user:         get(/(?:for invalid user|for user|by)\s+(\S+)/i) ?? get(/(\w+)\s*:/),
      src_ip:       get(/from\s+([\d.]+)/i),
      src_port:     get(/port\s+(\d+)/i) ? parseInt(get(/port\s+(\d+)/i), 10) : null,
      dest_ip:      null,
      dest_port:    null,
      host:         get(/^\w{3}\s+\d+\s+[\d:]+\s+(\S+)\s+/),
      resource:     null,
      command_line: get(/COMMAND=(.+)$/m),
      process_name: get(/^\w+\s+\S+\s+(\S+)\[/),
    }
  }
}
