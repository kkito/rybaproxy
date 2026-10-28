export class RybaModal extends HTMLElement {
  constructor() { super(); }
  connectedCallback(): void {
    this.addEventListener('click', e => {
      const t = e.target as HTMLElement;
      if (t === this || t.hasAttribute('data-close')) this.close();
    });
  }
  open(): void { this.classList.add('open'); }
  close(): void { this.classList.remove('open'); }
}
customElements.define('ryba-modal', RybaModal);
