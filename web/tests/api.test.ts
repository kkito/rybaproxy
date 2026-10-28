import { describe, it, expect, vi } from 'vitest'
import { api, unwrapPage } from '../src/main.js'

describe('api client', () => {
  it('throws on ok=false', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      json: async () => ({ ok: false, error: { message: 'bad' } }),
      status: 400
    })
    await expect(api('/api/test')).rejects.toThrow('bad')
  })
  it('returns data on ok=true', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      json: async () => ({ ok: true, data: { ok: true } }),
      status: 200
    })
    const res = await api<{ ok: boolean }>('/api/test')
    expect(res.data!.ok).toBe(true)
  })
  it('unwrapPage defaults', () => {
    expect(unwrapPage({ data: [1], total: 1, limit: 20, offset: 0 }).rows).toEqual([1])
    expect(unwrapPage({}).rows).toEqual([])
  })
})
