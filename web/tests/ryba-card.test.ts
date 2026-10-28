import { describe, it, expect } from 'vitest'
import '../src/ryba-card.js'

describe('ryba-card', () => {
  it('defines custom element', () => {
    expect(customElements.get('ryba-card')).toBeDefined()
  })
  it('renders with slots', () => {
    const el = document.createElement('ryba-card')
    el.innerHTML = '<span slot="eyebrow">DNS</span><span slot="title">DNS 设置</span><div>body</div>'
    document.body.appendChild(el)
    expect(el.innerHTML).toContain('DNS 设置')
    document.body.removeChild(el)
  })
})
