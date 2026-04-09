import { Redis } from '@upstash/redis'

const redis = new Redis({
  url:   process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
})

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url)
    const sessionId = (searchParams.get('sessionId') ?? 'default').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64)
    const prefix = `session:${sessionId}:`

    const [ipKeys, userKeys] = await Promise.all([
      redis.keys(`${prefix}ip:*`),
      redis.keys(`${prefix}user:*`),
    ])

    const allKeys = [...ipKeys, ...userKeys]
    if (!allKeys.length) return Response.json({ indicators: [], totalHits: 0, uniqueAssets: 0, activeCampaigns: 0 })

    const values = await Promise.all(allKeys.map(k => redis.get(k)))
    const indicators = values.map((v, i) => {
      if (!v) return null
      const rawKey = allKeys[i]
      const displayKey = rawKey.split(':').slice(2).join(':')
      return { key: displayKey, ...v }
    }).filter(Boolean)
    const totalHits = indicators.reduce((sum, h) => sum + (h.count ?? 0), 0)
    const uniqueAssets = new Set(indicators.flatMap(h => h.assets ?? [])).size
    const activeCampaigns = indicators.filter(h => (h.count ?? 0) >= 2 && (h.assets?.length ?? 0) >= 2).length

    return Response.json({ indicators, totalHits, uniqueAssets, activeCampaigns })
  } catch (err) {
    console.error('[ARBITER] Redis insights failed:', err)
    return Response.json({ indicators: [], totalHits: 0, uniqueAssets: 0, activeCampaigns: 0 })
  }
}
