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
    if (/^(GetObject|PutObject|DeleteObject|ListObjects|HeadObject)/i.test(eventName)) return 'network'
    if (/^(AssumeRole|GetSessionToken|ConsoleLogin)/i.test(eventName)) return 'auth'
    if (/^(RunInstances|TerminateInstances|StartInstances|StopInstances)/i.test(eventName)) return 'process'
    if (/^(AttachUserPolicy|DetachUserPolicy|PutUserPolicy|AttachRolePolicy|DetachRolePolicy|PutRolePolicy|CreateUser|DeleteUser|CreateRole|DeleteRole|AddUserToGroup|RemoveUserFromGroup)/i.test(eventName)) return 'privilege'
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
      host:         obj.recipientAccountId ?? obj.requestParameters?.bucketName ?? null,
      target_user:  obj.requestParameters?.userName ?? obj.requestParameters?.roleName ?? null,
      resource:     obj.requestParameters?.bucketName ?? obj.requestParameters?.instanceId ?? null,
      command_line: null,
      process_name: obj.eventSource ?? null,
    }
  }
}
