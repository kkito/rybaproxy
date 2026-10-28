import { describe, it, expect } from 'vitest'
import { dnsStatusHtml, nsTableHtml, cacheTableHtml, logsTableHtml } from '../src/pages/dns.js'

describe('dns page', () => {
  it('status shows proxy and counts', () => {
    const h = dnsStatusHtml({ proxy: 'none', cache_count: 2, log_count: 5, fallback: ['1.1.1.1'] })
    expect(h).toContain('none')
    expect(h).toContain('2')
    expect(h).toContain('1.1.1.1')
  })
  it('ns table escapes url', () => {
    const h = nsTableHtml([{ type: 1, url: '<x>', host: 'h', proxy: '' }])
    expect(h).toContain('&lt;x&gt;')
  })
  it('cache table shows domain and ttl', () => {
    const h = cacheTableHtml([{ domain: 'a.com', class: 1, resolver_id: 'r', ip: '1.2.3.4', ttl_left: 60, hits: 3, negative: false }])
    expect(h).toContain('a.com')
    expect(h).toContain('1.2.3.4')
  })
  it('logs table shows status', () => {
    const h = logsTableHtml([{ ts: 1, domain: 'b.com', class: 1, resolver_id: 'r', via_proxy: false, duration_ms: 5, status: 'ok', ip_count: 1, from_cache: true }])
    expect(h).toContain('b.com')
    expect(h).toContain('ok')
  })
})
