// Applies a saved light/dark choice before first paint (the CSP forbids inline scripts).
// The storage key is scoped to the deployment's base path, which is where this file lives.
(function () {
  try {
    var base = new URL('.', document.currentScript.src).pathname;
    var t = localStorage.getItem(base + 'theme');
    if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t);
  } catch (e) {
    /* storage blocked: follow the OS setting */
  }
})();
