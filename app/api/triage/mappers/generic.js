// ── GENERIC FALLBACK MAPPER ────────────────────────────────────────────────────
// Last resort — extracts only what regex can find. Always sets is_generic = true.

export function mapGeneric(text) {
  const get = (pattern) => text.match(pattern)?.[1]?.trim() ?? null

  return {
    meta: {
      vendor_origin: 'unknown',
      raw_event_id:  null,
      is_generic:    true,
    },
    acs_data: {
      timestamp:    get(/(\d{4}-\d{2}-\d{2}T[\d:.Z]+)/),
      event_type:   'unknown',
      event_outcome: 'unknown',
      action:       'unknown',
      user:         get(/(?:user_?name|account|actor|USER|USERNAME)[=:\s]+([A-Za-z0-9._@-]+)/i),
      src_ip:       get(/(?:src_ip|source_ip|sourceip|src|source|from|SOURCE_IP|SRC_IP)[=:\s]+([\d.]+)/i),
      src_port:     null,
      dest_ip:      get(/(?:dst_ip|dest_ip|destip|dst|dest|to|DEST_IP|DST_IP)[=:\s]+([\d.]+)/i),
      dest_port:    null,
      host:         get(/(?:host|hostname|computer|HOSTNAME|HOST)[=:\s]+(\S+)/i),
      resource:     null,
      command_line: (() => {
        const sudoCmd = get(/COMMAND=(.+)$/m)
        const cronCmd = get(/CMD\s+\((.+)\)$/m)
        const genericCmd = get(/CMD=(.+)$/m)
        const quotedCmd = get(/(?:command|cmd|exec|execute|process)[=:\s]+"([^"]+)"/im)
        const unquotedCmd = get(/(?:command|cmd|exec|execute|process)[=:\s]+([^\s;|&]+(?:\s+[^\s;|&]+)*)/im)
        return sudoCmd ?? cronCmd ?? genericCmd ?? quotedCmd ?? unquotedCmd ?? null
      })(),
      process_name: null,
    }
  }
}
