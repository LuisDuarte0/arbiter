// ── AWS CLOUDTRAIL MAPPER ──────────────────────────────────────────────────────

export function mapCloudTrail(text) {
  let obj = null
  try {
    const jsonMatch = text.match(/\{[\s\S]+\}/)
    if (jsonMatch) obj = JSON.parse(jsonMatch[0])
  } catch { /* not JSON */ }

  if (!obj) return null

  const eventName = obj.eventName ?? ''
  const action = eventName.toLowerCase() || 'unknown'

  const event_type = (() => {
    if (/^(GetObject|PutObject|DeleteObject)/i.test(eventName)) return 'network'
    if (/^(AssumeRole|GetSession|CreateUser|DeleteUser)/i.test(eventName)) return 'auth'
    if (/^(RunInstances|TerminateInstances)/i.test(eventName)) return 'process'
    if (/^(AttachPolicy|DetachPolicy|PutUserPolicy)/i.test(eventName)) return 'privilege'
    return 'unknown'
  })()

  const event_outcome = obj.errorCode ? 'failure' : 'success'

  return {
    meta: {
      vendor_origin: 'cloudtrail',
      raw_event_id:  obj.eventID ?? null,
    },
    acs_data: {
      timestamp:    obj.eventTime ?? null,
      event_type,
      event_outcome,
      action,
      user:         obj.userIdentity?.userName ?? obj.userIdentity?.arn ?? null,
      src_ip:       obj.sourceIPAddress ?? null,
      src_port:     null,
      dest_ip:      null,
      dest_port:    null,
      host:         obj.recipientAccountId ?? null,
      resource:     obj.requestParameters?.bucketName ?? obj.requestParameters?.instanceId ?? null,
      command_line: null,
      process_name: obj.eventSource ?? null,
    }
  }
}
