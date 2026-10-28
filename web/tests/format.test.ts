import { describe, it, expect } from 'vitest'
import { esc, fmtBytes, sparkline, cnText, upName, geoLabel } from '../src/main.js'

describe('format', () => {
  it('esc escapes html', () => {
    expect(esc('<a>"&')).toBe('&lt;a&gt;&quot;&amp;')
  })
  it('fmtBytes units', () => {
    expect(fmtBytes(500)).toBe('500 B')
    expect(fmtBytes(2048)).toBe('2.0 KB')
    expect(fmtBytes(1048576)).toBe('1.0 MB')
  })
  it('sparkline empty', () => {
    expect(sparkline([])).toBe('')
    expect(sparkline([1, 2]).length).toBeGreaterThan(0)
  })
  it('cnText unknown', () => {
    expect(cnText(null)).toContain('未知')
    expect(cnText(true)).toBe('CN')
    expect(cnText(false)).toBe('非CN')
  })
  it('upName fallback', () => {
    expect(upName([{ id: 1, name: 'a' }], 1)).toBe('a')
    expect(upName([], 9)).toBe('id(9)')
  })
  it('geoLabel', () => {
    expect(geoLabel({})).toBe('—')
    expect(geoLabel({ geo_ip: 'cn' })).toContain('geoip:cn')
  })
})
