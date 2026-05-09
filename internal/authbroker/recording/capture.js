// capture.js — content script injected into every page during DAST recording.
// Listens for click and input events and emits {kind,selector,t} payloads
// through the __sentinel_emit CDP runtime binding. VALUES ARE NEVER EMITTED.
//
// Selector ranking prefers stable test attributes, falls back to id / name,
// and finally a bounded CSS path with :nth-of-type tie-breaks.
(() => {
  const STABLE_ATTRS = ['data-testid', 'data-test', 'data-cy'];

  function cssEscape(s) {
    return (typeof CSS !== 'undefined' && CSS.escape) ? CSS.escape(s) : String(s).replace(/[^a-zA-Z0-9_\-]/g, '\\$&');
  }

  function rankSelector(el) {
    if (!el || el.nodeType !== 1) return '';
    for (const a of STABLE_ATTRS) {
      const v = el.getAttribute && el.getAttribute(a);
      if (v) return '[' + a + '="' + cssEscape(v) + '"]';
    }
    if (el.id) return '#' + cssEscape(el.id);
    if (el.name) return el.tagName.toLowerCase() + '[name="' + cssEscape(el.name) + '"]';
    const path = [];
    let cur = el;
    while (cur && cur.nodeType === 1 && path.length < 6) {
      let part = cur.tagName.toLowerCase();
      if (cur.parentElement) {
        const sibs = Array.from(cur.parentElement.children).filter(s => s.tagName === cur.tagName);
        if (sibs.length > 1) part += ':nth-of-type(' + (sibs.indexOf(cur) + 1) + ')';
      }
      path.unshift(part);
      cur = cur.parentElement;
    }
    return path.join(' > ');
  }

  function emit(kind, selector) {
    if (typeof __sentinel_emit !== 'function') return;
    try {
      __sentinel_emit(JSON.stringify({ kind: kind, selector: selector, t: Date.now() }));
    } catch (e) { /* swallow */ }
  }

  document.addEventListener('click', (e) => {
    emit('click', rankSelector(e.target));
  }, true);

  document.addEventListener('input', (e) => {
    // VALUE INTENTIONALLY OMITTED — selector only.
    emit('fill', rankSelector(e.target));
  }, true);
})();
