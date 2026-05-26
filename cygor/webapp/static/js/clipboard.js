/**
 * Clipboard helper with fallback for self-signed HTTPS contexts.
 *
 * navigator.clipboard.writeText() requires a "secure context" — a page served
 * over HTTPS with a trusted certificate or via localhost.  When Cygor runs with
 * a self-signed cert the browser rejects the call.  This helper tries the
 * modern API first and falls back to the legacy execCommand('copy') approach.
 */
function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  // Fallback: temporary textarea + execCommand
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    document.body.removeChild(ta);
    return Promise.resolve();
  } catch (err) {
    document.body.removeChild(ta);
    return Promise.reject(err);
  }
}
