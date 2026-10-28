export class RybaStat extends HTMLElement {
  private _rendered = false;
  static get observedAttributes(): string[] { return ['value', 'label', 'trend', 'spark']; }
  constructor() { super(); this._rendered = false; }
  connectedCallback(): void { if (!this._rendered) { this._rendered = true; this.render(); } }
  attributeChangedCallback(): void { if (this._rendered) this.render(); }
  render(): void {
    const value = this.getAttribute('value') ?? '';
    const label = this.getAttribute('label') ?? '';
    const trend = this.getAttribute('trend') ?? '';
    const spark = this.getAttribute('spark') ?? '';
    this.innerHTML = `
      <div class="stat-value num">${value}</div>
      <div class="stat-label">${label}</div>
      ${trend ? `<div class="stat-trend">↗ ${trend}</div>` : ''}
      <svg class="spark" viewBox="0 0 120 36" preserveAspect="none">
        <polyline fill="none" stroke="#8FA888" stroke-width="1.6" points="${spark}"/>
      </svg>`;
  }
}
customElements.define('ryba-stat', RybaStat);
