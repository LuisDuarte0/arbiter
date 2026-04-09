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
      user:         get(/(?:user|username|account)[=:\s]+(\S+)/i),
      src_ip:       get(/(?:src|source|from)[=:\s]+([\d.]+)/i),
      src_port:     null,
      dest_ip:      get(/(?:dst|dest|to)[=:\s]+([\d.]+)/i),
      dest_port:    null,
      host:         get(/(?:host|hostname|computer)[=:\s]+(\S+)/i),
      resource:     null,
      command_line: null,
      process_name: null,
    }
  }
}
