import type { UpstreamTable } from '../src/upstream-table.js';
import type { RuleTable } from '../src/rule-table.js';
import type { SessionTable } from '../src/session-table.js';
import type { RybaModal } from '../src/ryba-modal.js';

declare global {
  interface HTMLElementTagNameMap {
    'upstream-table': UpstreamTable;
    'rule-table': RuleTable;
    'session-table': SessionTable;
    'ryba-modal': RybaModal;
  }
}
export {};
