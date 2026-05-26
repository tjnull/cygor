/**
 * Cygor Shared Utility Functions
 * Consolidated from per-template duplicates. Loaded globally via base.html.
 */

/**
 * Escape HTML special characters to prevent XSS.
 * @param {string} text - Raw text to escape
 * @returns {string} HTML-safe string
 */
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Escape a value for CSV output (double-quote escaping).
 * @param {*} value
 * @returns {string}
 */
function escapeCSV(value) {
  if (!value) return '';
  return String(value).replace(/"/g, '""');
}
