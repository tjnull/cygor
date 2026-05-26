/**
 * Cygor Terminal & Timer Utilities
 * Consolidated from per-template duplicates. Loaded globally via base.html.
 */

/**
 * Elapsed timer for running tasks/scans.
 * Displays HH:MM:SS or MM:SS in a target element.
 *
 * Usage:
 *   window.cygorTimer.start(startDate);   // Date object
 *   window.cygorTimer.stop();
 *
 * Expects an element with id="elapsedTimeInline" in the page.
 * Used by: task_detail.html, credrecon_scan_detail.html
 */
window.cygorTimer = (function () {
  var _interval = null;
  var _startTime = null;

  function _update() {
    if (!_startTime) return;
    var now = new Date();
    var diff = now - _startTime;
    if (diff < 0) diff = 0;

    var hours = Math.floor(diff / 3600000);
    var minutes = Math.floor((diff % 3600000) / 60000);
    var seconds = Math.floor((diff % 60000) / 1000);

    var timeString;
    if (hours > 0) {
      timeString = hours + ':' + String(minutes).padStart(2, '0') + ':' + String(seconds).padStart(2, '0');
    } else {
      timeString = String(minutes).padStart(2, '0') + ':' + String(seconds).padStart(2, '0');
    }

    var el = document.getElementById('elapsedTimeInline');
    if (el) el.textContent = timeString;
  }

  return {
    start: function (startDate) {
      if (_interval) return;
      if (!startDate || isNaN(startDate.getTime())) {
        console.error('[Timer] Cannot start timer: invalid startTime', startDate);
        return;
      }
      _startTime = startDate;
      _update();
      _interval = setInterval(_update, 1000);
    },
    stop: function () {
      if (_interval) {
        clearInterval(_interval);
        _interval = null;
      }
    },
    reset: function () {
      this.stop();
      _startTime = null;
      var el = document.getElementById('elapsedTimeInline');
      if (el) el.textContent = '00:00';
    }
  };
})();
