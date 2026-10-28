import { describe, it, expect } from 'vitest'
import '../src/ryba-stat.js'

describe('ryba-stat', () => {
  it('defines element', () => {
    expect(customElements.get('ryba-stat')).toBeDefined()
  })
  it('renders value/label/trend', () => {
    const el = document.createElement('ryba-stat')
    el.setAttribute('value', '42')
    el.setAttribute('label', '会话')
    el.setAttribute('trend', '+3')
    document.body.appendChild(el)
    expect(el.innerHTML).toContain('42')
    expect(el.innerHTML).toContain('会话')
    document.body.removeChild(el)
  })
})
