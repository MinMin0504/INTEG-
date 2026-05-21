/**
 * @fileoverview CompliTrack — Utility functions.
 * Date formatting, validation, debounce, retry logic, and helpers.
 */

/**
 * Format an ISO timestamp to a readable string.
 * @param {string|Date} ts - Timestamp to format.
 * @param {boolean} [includeTime=true] - Include time portion.
 * @returns {string} Formatted date string.
 */
export function formatDate(ts, includeTime = true) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return '—';
  const opts = { year: 'numeric', month: 'short', day: 'numeric' };
  if (includeTime) { opts.hour = '2-digit'; opts.minute = '2-digit'; }
  return d.toLocaleDateString('en-PH', opts);
}

/**
 * Format a date for date inputs (YYYY-MM-DD).
 * @param {string|Date} ts
 * @returns {string}
 */
export function toInputDate(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toISOString().split('T')[0];
}

/**
 * Debounce a function.
 * @param {Function} fn - Function to debounce.
 * @param {number} ms - Delay in milliseconds.
 * @returns {Function}
 */
export function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

/**
 * Retry an async function with exponential back-off.
 * @param {Function} fn - Async function to execute.
 * @param {number} [retries=3] - Maximum retry attempts.
 * @returns {Promise<*>}
 */
export async function withRetry(fn, retries = 3) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt === retries) throw err;
      await new Promise(r => setTimeout(r, Math.pow(2, attempt) * 500));
    }
  }
}

/**
 * Escape HTML entities to prevent XSS.
 * @param {string} str
 * @returns {string}
 */
export function escapeHtml(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(str || ''));
  return div.innerHTML;
}

/**
 * Validate an email address format.
 * @param {string} email
 * @returns {boolean}
 */
export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Return a CSS class suffix for a given status.
 * @param {string} status
 * @returns {string}
 */
export function statusClass(status) {
  const s = (status || '').toLowerCase();
  if (['approved', 'compliant', 'success', 'resolved', 'ready'].includes(s)) return 'ok';
  if (['rejected', 'non-compliant', 'failed', 'high'].includes(s)) return 'danger';
  if (['pending', 'needs review', 'open', 'alert', 'in progress', 'under review', 'medium'].includes(s)) return 'warn';
  return '';
}

/**
 * Build a status badge HTML string.
 * @param {string} status
 * @returns {string}
 */
export function statusBadge(status) {
  const cls = statusClass(status);
  const dotCls = cls === 'ok' ? 'status-dot--ok' : cls === 'danger' ? 'status-dot--danger' : cls === 'warn' ? 'status-dot--warn' : '';
  const tagCls = cls === 'ok' ? 'ok' : cls === 'danger' ? 'danger' : 'warn';
  return `<span class="tag tag--dark ${tagCls}"><span class="status-dot ${dotCls}"></span>${escapeHtml(status)}</span>`;
}

/**
 * Show a toast notification in the UI.
 * @param {string} message
 * @param {'success'|'error'|'info'} [type='info']
 * @param {number} [duration=4000]
 */
export function showToast(message, type = 'info', duration = 4000) {
  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  const toast = document.createElement('div');
  toast.className = `toast toast--${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('toast--visible'));
  setTimeout(() => {
    toast.classList.remove('toast--visible');
    toast.addEventListener('transitionend', () => toast.remove());
  }, duration);
}

/**
 * Show a confirmation dialog (promise-based).
 * @param {string} title
 * @param {string} message
 * @returns {Promise<boolean>}
 */
export function confirmDialog(title, message) {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay modal-overlay--active';
    overlay.innerHTML = `
      <div class="modal glass-panel">
        <h3 class="modal__title">${escapeHtml(title)}</h3>
        <p class="modal__message">${escapeHtml(message)}</p>
        <div class="modal__actions">
          <button type="button" class="btn-ghost" data-action="cancel">Cancel</button>
          <button type="button" class="btn-orange btn-orange--sm" data-action="confirm">Confirm</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => { overlay.remove(); resolve(false); });
    overlay.querySelector('[data-action="confirm"]').addEventListener('click', () => { overlay.remove(); resolve(true); });
  });
}

/**
 * Create a skeleton loading row for tables.
 * @param {number} cols - Number of columns.
 * @param {number} [rows=5] - Number of skeleton rows.
 * @returns {string}
 */
export function skeletonRows(cols, rows = 5) {
  const cell = '<td><div class="skeleton skeleton--text"></div></td>';
  const row = `<tr class="skeleton-row">${cell.repeat(cols)}</tr>`;
  return row.repeat(rows);
}

/**
 * Simple in-memory cache with TTL.
 */
export class SimpleCache {
  constructor(ttlMs = 5 * 60 * 1000) {
    this._store = new Map();
    this._ttl = ttlMs;
  }
  get(key) {
    const entry = this._store.get(key);
    if (!entry) return null;
    if (Date.now() - entry.ts > this._ttl) { this._store.delete(key); return null; }
    return entry.data;
  }
  set(key, data) {
    this._store.set(key, { data, ts: Date.now() });
  }
  clear() { this._store.clear(); }
}
