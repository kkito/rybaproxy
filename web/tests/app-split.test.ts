import { describe, it, expect } from 'vitest'
import { upstreamRowHtml, upstreamOptionsHtml } from '../src/upstreams.js'
import { ruleRowHtml } from '../src/rules.js'
import { sessionRowHtml, pagerHtml } from '../src/sessions.js'
import { heatLevel, heroValues } from '../src/dashboard.js'
import { geoDbText, geoStatusText, geoSrcText, geoCheckText } from '../src/pages/geo.js'

describe('app split: upstreams', () => {
  it('upstreamRowHtml escapes name and shows addr', () => {
    const h = upstreamRowHtml({ id: 1, name: '<x>', type: 'http', host: 'h', port: 8080, enabled: true })
    expect(h).toContain('&lt;x&gt;')
    expect(h).toContain('h:8080')
    expect(h).toContain('启用')
  })
  it('upstreamOptionsHtml falls back to direct', () => {
    expect(upstreamOptionsHtml([])).toContain('direct')
  })
})

describe('app split: rules', () => {
  it('ruleRowHtml shows geo and upstream name', () => {
    const h = ruleRowHtml(
      { id: 1, priority: 10, domain_pattern: '*.a.com', ip_cidr: '', geo_ip: 'cn', geo_site: '', port: 0, protocol: 'any', upstream_id: 2 },
      [{ id: 2, name: 'u2' }],
    )
    expect(h).toContain('geoip:cn')
    expect(h).toContain('u2')
  })
})

describe('app split: sessions', () => {
  it('sessionRowHtml marks active', () => {
    const h = sessionRowHtml({ protocol: 'http', client_ip: '1.1.1.1', target_host: 'e.com', target_port: 80, status: 0, bytes_up: 10, bytes_down: 20 })
    expect(h).toContain('活跃')
  })
  it('pagerHtml shows cur/total', () => {
    const h = pagerHtml({ rows: [], total: 40, limit: 20, offset: 20 })
    expect(h).toContain('2 / 2')
  })
})

describe('app split: geo', () => {
  it('geoDbText handles missing', () => {
    expect(geoDbText(undefined, 'geoip')).toBe('geoip: 未下载')
    expect(geoDbText({ exists: true, size: 2097152, cn_count: 7 }, 'geoip')).toContain('2.0MB')
  })
  it('geoStatusText joins both dbs', () => {
    expect(geoStatusText({ geoip: { exists: false }, geosite: { exists: false } })).toContain('未下载')
  })
  it('geoSrcText shows proxy', () => {
    expect(geoSrcText({ dir: '/d', geoip: { url: 'https://x/y' } })).toContain('直连下载')
    expect(geoSrcText({ dir: '/d', proxy: 'p', geoip: {} })).toContain('代理: p')
  })
  it('geoCheckText warns when db not loaded', () => {
    const t = geoCheckText({ ips: [], geoip_cn: null, geosite_cn: true, db_loaded: false, matched_rule: 'r', upstream: { id: 1 } })
    expect(t).toContain('未知')
    expect(t).toContain('IP 库未加载')
  })
})

describe('app split: dashboard', () => {
  it('heatLevel buckets frac', () => {
    expect(heatLevel(0.1)).toBe(0)
    expect(heatLevel(0.9)).toBe(3)
  })
  it('heroValues picks today up/down', () => {
    const v = heroValues({ total_sessions: 5, errors: 1, dropped: 2 }, [{ day: 'd', bytes_up: 100, bytes_down: 200, sessions: 1 }])
    expect(v.sessions).toBe('5')
    expect(v.errors).toBe('3')
  })
})
