// ── AWS CLOUDTRAIL MAPPER ──────────────────────────────────────────────────────
// Maps CloudTrail JSON to ACS v2.0 provenance-wrapped object.
// Source format: 'raw:json:<dot_path>' for fields read directly from JSON,
//               'derived:*' for computed classifications.
// action ('raw:json:eventName') and event_type ('derived:event_name_classification')
// have different sources → independent. event_outcome reads errorCode directly
// ('raw:json:errorCode') → independent from action.

const w = (value, source) => ({ value: value ?? null, source: (value != null && value !== '') ? source : null })

export function mapCloudTrail(text) {
  let obj = null
  try {
    const jsonMatch = text.match(/\{[\s\S]+\}/)
    if (jsonMatch) obj = JSON.parse(jsonMatch[0])
  } catch { /* not JSON */ }

  if (!obj) return null

  const eventName = obj.eventName ?? ''
  const actionVal = eventName.toLowerCase() || 'unknown'

  const eventTypeVal = (() => {
    if (/^(GetObject|PutObject|DeleteObject|ListObjects|HeadObject)/i.test(eventName))            return 'network'
    if (/^(AssumeRole|GetSessionToken|ConsoleLogin)/i.test(eventName))                            return 'auth'
    if (/^(RunInstances|TerminateInstances|StartInstances|StopInstances)/i.test(eventName))       return 'process'
    if (/^(AttachUserPolicy|DetachUserPolicy|PutUserPolicy|AttachRolePolicy|DetachRolePolicy|PutRolePolicy|CreateUser|DeleteUser|CreateRole|DeleteRole|AddUserToGroup|RemoveUserFromGroup)/i.test(eventName)) return 'privilege'
    return 'unknown'
  })()

  const eventOutcomeVal = obj.errorCode ? 'failure' : 'success'

  const userVal      = obj.userIdentity?.userName ?? obj.userIdentity?.arn ?? null
  const userSrc      = obj.userIdentity?.userName ? 'raw:json:userIdentity.userName'
                     : obj.userIdentity?.arn      ? 'raw:json:userIdentity.arn'
                     : null

  const hostVal      = obj.recipientAccountId ?? obj.requestParameters?.bucketName ?? null
  const hostSrc      = obj.recipientAccountId            ? 'raw:json:recipientAccountId'
                     : obj.requestParameters?.bucketName ? 'raw:json:requestParameters.bucketName'
                     : null

  const targetUserVal = obj.requestParameters?.userName ?? obj.requestParameters?.roleName ?? null
  const targetUserSrc = obj.requestParameters?.userName ? 'raw:json:requestParameters.userName'
                      : obj.requestParameters?.roleName ? 'raw:json:requestParameters.roleName'
                      : null

  const resourceNameVal = obj.requestParameters?.bucketName ?? obj.requestParameters?.instanceId ?? null
  const resourceNameSrc = obj.requestParameters?.bucketName  ? 'raw:json:requestParameters.bucketName'
                        : obj.requestParameters?.instanceId  ? 'raw:json:requestParameters.instanceId'
                        : null

  return {
    meta: {
      vendor_origin: 'cloudtrail',
      raw_event_id:  obj.eventID ?? null,
    },
    acs_data: {
      timestamp:     w(obj.eventTime,                                       'raw:json:eventTime'),
      event_type:    { value: eventTypeVal,     source: eventTypeVal    !== 'unknown' ? 'derived:event_name_classification' : null },
      event_outcome: w(eventOutcomeVal,                                     'raw:json:errorCode'),
      action:        w(actionVal !== 'unknown' ? actionVal : null,          'raw:json:eventName'),
      user:          { value: userVal,          source: userSrc },
      src_ip:        w(obj.sourceIPAddress,                                 'raw:json:sourceIPAddress'),
      src_port:      w(null,                                                 null),
      dest_ip:       w(null,                                                 null),
      dest_port:     w(null,                                                 null),
      host:          { value: hostVal,          source: hostSrc },
      object_name:   w(null,                                                 null),
      task_name:     w(null,                                                 null),
      service_name:  w(null,                                                 null),
      resource_name: { value: resourceNameVal,  source: resourceNameSrc },
      command_line:  w(null,                                                 null),
      process_name:  w(obj.eventSource,                                      'raw:json:eventSource'),
      count:         w(null,                                                  null),
      logon_type:    w(null,                                                  null),
      target_user:   { value: targetUserVal,    source: targetUserSrc },
    }
  }
}
