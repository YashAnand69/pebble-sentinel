/* Shared product navigation: native links remain usable without this enhancement. */
(() => {
  const products = new Map([
    ['pebble-peach-kappa.vercel.app', 'language'],
    ['pebble-llm.vercel.app', 'model'],
    ['pebble-sentinel.vercel.app', 'sentinel'],
  ]);
  const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
  const motionOff = () => {
    let saved = false;
    try { saved = localStorage.getItem('pebble-motion') === 'off' || localStorage.getItem('pebble-motion-v1') === 'reduced'; } catch {}
    return preference.matches || saved || document.documentElement.dataset.motion === 'off' || document.documentElement.dataset.pebbleMotion === 'reduced';
  };
  let overlay;
  let timer;
  const clear = () => { clearTimeout(timer); overlay?.remove(); overlay = undefined; };
  const show = (product, arriving) => {
    clear();
    if (motionOff()) return;
    overlay = document.createElement('div');
    overlay.className = `pebble-transition ${arriving ? 'is-arriving' : 'is-leaving'} ${product === 'sentinel' ? 'is-sentinel' : ''}`;
    overlay.setAttribute('aria-hidden', 'true');
    const pigment = document.createElement('span');
    pigment.className = 'pebble-transition-pigment';
    overlay.append(pigment);
    document.body.append(overlay);
    timer = setTimeout(clear, 600);
  };
  const entry = new URL(window.location.href);
  const product = entry.searchParams.get('pebble-entry');
  if (['language', 'model', 'sentinel'].includes(product)) {
    show(product, true);
    entry.searchParams.delete('pebble-entry');
    history.replaceState(history.state, '', entry.href);
  }
  document.addEventListener('click', event => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const link = event.target instanceof Element ? event.target.closest('a[href]') : null;
    if (!link || link.hasAttribute('download') || (link.target && link.target !== '_self')) return;
    const destination = new URL(link.href, window.location.href);
    const target = products.get(destination.hostname);
    if (!target || destination.origin === window.location.origin || !['https:', 'http:'].includes(destination.protocol)) return;
    if (motionOff()) return;
    destination.searchParams.set('pebble-entry', target);
    event.preventDefault();
    show(target, false);
    // No interaction-blocking delay: the receiving app supplies the entrance.
    window.location.assign(destination.href);
  });
  window.addEventListener('pageshow', event => { if (event.persisted) clear(); });
  preference.addEventListener('change', () => { if (motionOff()) clear(); });
  window.addEventListener('pebble-motion-change', () => { if (motionOff()) clear(); });
})();
