// ── GENERIC FALLBACK MAPPER ────────────────────────────────────────────────────
// Last resort — extracts only what regex can find. Always sets is_generic = true.
// Source format: 'raw:text_regex:<semantic_id>'
// event_type / event_outcome / action are hardcoded 'unknown' — source: null
// because no real extraction occurred. This prevents them from passing provenance
// independence checks, so generic ACS behavioral signals will not fire on generic logs.

const w = (value, source) => ({ value: value ?? null, source: (value != null && value !== '') ? source : null })

export function mapGeneric(text) {
  const get = (pattern) => text.match(pattern)?.[1]?.trim() ?? null

  const cmdLineVal = (() => {
    const sudoCmd    = get(/COMMAND=(.+)$/m)
    const cronCmd    = get(/CMD\s+\((.+)\)$/m)
    const genericCmd = get(/CMD=(.+)$/m)
    const quotedCmd  = get(/(?:command|cmd|exec|execute|process)[=:\s]+"([^"]+)"/im)
    const unquotedCmd = get(/(?:command|cmd|exec|execute|process)[=:\s]+([^\s;|&]+(?:\s+[^\s;|&]+)*)/im)
    return sudoCmd ?? cronCmd ?? genericCmd ?? quotedCmd ?? unquotedCmd ?? null
  })()

  const userVal    = get(/(?:user_?name|account|actor|USER|USERNAME)[=:\s]+([A-Za-z0-9._@-]+)/i)
  const srcIpVal   = get(/(?:src_ip|source_ip|sourceip|src|source|from|SOURCE_IP|SRC_IP)[=:\s]+([\d.]+)/i)
  const destIpVal  = get(/(?:dst_ip|dest_ip|destip|dst|dest|to|DEST_IP|DST_IP)[=:\s]+([\d.]+)/i)
  const hostVal    = get(/(?:host|hostname|computer|HOSTNAME|HOST)[=:\s]+(\S+)/i)
  const tsVal      = get(/(\d{4}-\d{2}-\d{2}T[\d:.Z]+)/)

  return {
    meta: {
      vendor_origin: 'unknown',
      raw_event_id:  null,
      is_generic:    true,
    },
    acs_data: {
      timestamp:     w(tsVal,       'raw:text_regex:timestamp'),
      event_type:    { value: 'unknown', source: null },
      event_outcome: { value: 'unknown', source: null },
      action:        { value: 'unknown', source: null },
      user:          w(userVal,     'raw:text_regex:username'),
      src_ip:        w(srcIpVal,    'raw:text_regex:src_ip'),
      src_port:      w(null,         null),
      dest_ip:       w(destIpVal,   'raw:text_regex:dest_ip'),
      dest_port:     w(null,         null),
      host:          w(hostVal,     'raw:text_regex:hostname'),
      object_name:   w(null,         null),
      task_name:     w(null,         null),
      service_name:  w(null,         null),
      command_line:  w(cmdLineVal,  'raw:text_regex:command_line'),
      process_name:  w(null,         null),
      count:         w(null,         null),
      logon_type:    w(null,         null),
      target_user:   w(null,         null),
    }
  }
}
