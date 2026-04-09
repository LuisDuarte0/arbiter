import { Redis } from '@upstash/redis'

const redis = new Redis({
  url:   process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
})

export async function POST() {
  try {
    const keys = await redis.keys('ip:*')
    const userKeys = await redis.keys('user:*')
    const allKeys = [...keys, ...userKeys]
    if (allKeys.length > 0) {
      await Promise.all(allKeys.map(k => redis.del(k)))
    }
    return Response.json({ cleared: allKeys.length })
  } catch (err) {
    console.error('[ARBITER] Redis clear failed:', err)
    return Response.json({ error: err.message }, { status: 500 })
  }
}
