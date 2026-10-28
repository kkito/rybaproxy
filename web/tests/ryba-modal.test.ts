import { describe, it, expect } from 'vitest'
import '../src/ryba-modal.js'

describe('ryba-modal', () => {
  it('open/close toggles class', () => {
    const el = document.createElement('ryba-modal')
    document.body.appendChild(el)
    el.open()
    expect(el.classList.contains('open')).toBe(true)
    el.close()
    expect(el.classList.contains('open')).toBe(false)
    document.body.removeChild(el)
  })
})
