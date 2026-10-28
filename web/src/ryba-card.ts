export class RybaCard extends HTMLElement {
  constructor() {
    super();
    const shadow = this.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = `
      :host { display: block; background: var(--card,#f7f4ee); border: 1px solid var(--line,#e6dfd3); border-radius: 12px; padding: 24px 26px; box-shadow: 0 20px 40px -30px rgba(31,38,33,.9); position: relative; overflow: hidden; min-width: 0; }
      .card-head { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
      .card-title { font-family: "Playfair Display", serif; font-size: 1.25rem; }
      .card-eyebrow { font-size: .72rem; letter-spacing: .12em; text-transform: uppercase; color: var(--ink-soft,#6f6a5f); }
      .body { position: relative; z-index: 1; }
    `;
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div class="card-head">
        <div>
          <div class="card-eyebrow"><slot name="eyebrow"></slot></div>
          <div class="card-title"><slot name="title"></slot></div>
        </div>
        <div class="actions"><slot name="actions"></slot></div>
      </div>
      <div class="body"><slot></slot></div>
    `;
    shadow.appendChild(style);
    shadow.appendChild(wrap);
  }
}
customElements.define('ryba-card', RybaCard);
