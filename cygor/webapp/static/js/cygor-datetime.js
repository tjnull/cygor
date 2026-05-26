/**
 * Cygor Date/Time Formatting Utilities
 * Consolidated from per-template duplicates. Loaded globally via base.html.
 */

/**
 * Get the user's preferred timezone.
 * Priority: localStorage > browser Intl API > 'UTC'
 * Set via setCygorTimezone() when the user picks a timezone in the schedule form.
 */
function getCygorTimezone() {
  try {
    const saved = localStorage.getItem('cygor_preferred_timezone');
    if (saved) return saved;
  } catch (e) {}
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch (e) {}
  return 'UTC';
}

/**
 * Save the user's preferred timezone to localStorage.
 * Called when the user selects a non-UTC timezone in any schedule form.
 */
function setCygorTimezone(tz) {
  if (!tz) return;
  try {
    localStorage.setItem('cygor_preferred_timezone', tz);
  } catch (e) {}
}

/**
 * Format an ISO timestamp as a relative time string ("2m ago", "3h ago")
 * or full date if older than 24 hours.
 * Used by: tasks.html, task_detail.html, credrecon_scan_detail.html,
 *          settings_unified.html
 *
 * @param {string} isoString - ISO 8601 date string (from server, naive UTC)
 * @returns {string} Human-readable time string
 */
function formatTime(isoString) {
  if (!isoString) return '-';
  try {
    // Parse as UTC by appending 'Z' if not present
    let iso = isoString;
    if (!iso.endsWith('Z') && !iso.includes('+') && !iso.includes('-', 10)) {
      iso = iso + 'Z';
    }
    const date = new Date(iso);

    if (isNaN(date.getTime())) {
      console.error('Invalid date:', isoString);
      return '-';
    }
    const now = new Date();
    const diff = now - date;

    if (diff < 0) return 'Just now';
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
    if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
    const opts = { timeZoneName: 'short' };
    const tz = getCygorTimezone();
    if (tz) { try { opts.timeZone = tz; } catch (e) {} }
    return date.toLocaleDateString('en-US', opts) + ' ' + date.toLocaleTimeString('en-US', opts);
  } catch (e) {
    console.error('Date parse error:', e);
    return '-';
  }
}

/**
 * Format a date string as a human-readable date-time with timezone.
 * Used by: schedules.html, schedule_detail.html
 *
 * @param {string} dateStr - ISO 8601 date string
 * @param {string} [displayTz] - Optional IANA timezone to display in (e.g. "America/New_York")
 * @returns {string} e.g. "Jan 15, 2025, 02:30 PM EST"
 */
function formatDateTime(dateStr, displayTz) {
  if (!dateStr) return '';
  const opts = {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: true,
    timeZoneName: 'short'
  };
  if (displayTz) {
    try { opts.timeZone = displayTz; } catch (e) { /* ignore invalid tz */ }
  }
  return new Date(dateStr).toLocaleString('en-US', opts);
}

/**
 * Format a date string as a short date.
 * Used by: settings_unified.html
 *
 * @param {string} dateString - ISO 8601 date string
 * @returns {string} e.g. "Jan 15, 2025"
 */
function formatDate(dateString) {
  if (!dateString) return '';
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric'
  });
}

/**
 * Format a timestamp for display (short month + time).
 * Used by: credrecon_results.html
 *
 * @param {string} timestamp - ISO 8601 date string
 * @returns {string} e.g. "Jan 15, 2025, 02:30 PM"
 */
function formatTimestamp(timestamp) {
  if (!timestamp) return 'N/A';
  try {
    // Parse as UTC by appending 'Z' if not present (server sends naive UTC)
    let ts = timestamp;
    if (!ts.endsWith('Z') && !ts.includes('+') && !ts.includes('-', 10)) {
      ts = ts + 'Z';
    }
    const date = new Date(ts);
    if (isNaN(date.getTime())) return timestamp;
    const opts = {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
      timeZoneName: 'short'
    };
    const tz = getCygorTimezone();
    if (tz) {
      try { opts.timeZone = tz; } catch (e) { /* ignore invalid tz */ }
    }
    return date.toLocaleString('en-US', opts);
  } catch (e) { return timestamp; }
}

/**
 * Get a relative time string (handles both past and future).
 * Used by: schedule_detail.html
 *
 * @param {string} dateStr - ISO 8601 date string
 * @returns {string} e.g. "5m ago", "in 3h"
 */
function getRelativeTime(dateStr) {
  if (!dateStr) return '';
  const diff = Date.now() - new Date(dateStr).getTime();
  const absDiff = Math.abs(diff);
  const prefix = diff < 0 ? 'in ' : '';
  const suffix = diff >= 0 ? ' ago' : '';

  if (absDiff < 60000) return prefix + Math.floor(absDiff / 1000) + 's' + suffix;
  if (absDiff < 3600000) return prefix + Math.floor(absDiff / 60000) + 'm' + suffix;
  if (absDiff < 86400000) return prefix + Math.floor(absDiff / 3600000) + 'h' + suffix;
  return prefix + Math.floor(absDiff / 86400000) + 'd' + suffix;
}

/**
 * Format a duration in seconds to a human-readable string.
 * Used by: schedule_detail.html
 *
 * @param {number} seconds
 * @returns {string} e.g. "45s", "3m 12s", "1h 5m"
 */
function formatDuration(seconds) {
  if (seconds < 60) return Math.floor(seconds) + 's';
  if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + Math.floor(seconds % 60) + 's';
  return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
}

/**
 * Relative time for data grids ("just now", "2m ago", "3d ago").
 * Used by: credrecon_results.html
 *
 * @param {string} dateStr - ISO 8601 date string
 * @returns {string}
 */
function timeAgo(dateStr) {
  if (!dateStr) return '';
  try {
    const d = new Date(dateStr);
    const now = Date.now();
    const diff = now - d.getTime();
    if (diff < 0 || isNaN(diff)) return '';
    const sec = Math.floor(diff / 1000);
    if (sec < 60) return 'just now';
    const min = Math.floor(sec / 60);
    if (min < 60) return min + 'm ago';
    const hr = Math.floor(min / 60);
    if (hr < 24) return hr + 'h ago';
    const days = Math.floor(hr / 24);
    if (days < 30) return days + 'd ago';
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  } catch (e) { return ''; }
}
