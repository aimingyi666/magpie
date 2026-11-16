// The window's theme, for a page the plugin's own service draws.
//
// index.html is served by the window and hands its frame to this service,
// another origin, so the page cannot load the window's stylesheet or its
// bridge (_magpie/bridge.js). It can still talk to its parent: the window
// answers its own frame whatever the frame is showing, once that frame
// says hello, and sends a "theme" event on every change. This is only that
// part of internal/gui/pagebridge.js; options and reads go through this
// service, never the window.
//
// The theme arrives once at load and again whenever the reader switches
// light/dark, changes the font or the language, so an open page follows
// the window instead of waiting to be reopened.
(() => {
  const root = document.documentElement;

  function paint(theme) {
    if (!theme || typeof theme !== "object") return;
    root.dataset.theme = theme.dark ? "dark" : "light";
    root.style.colorScheme = theme.dark ? "dark" : "light";
    if (theme.lang) root.lang = theme.lang;
    for (const [name, value] of Object.entries(theme.tokens || {})) {
      if (typeof value === "string") root.style.setProperty(`--magpie-${name}`, value);
    }
  }

  const waiting = new Map();
  let next = 0;

  addEventListener("message", (event) => {
    if (event.source !== parent) return;
    const message = event.data;
    if (!message || message.magpie !== 1) return;
    if (message.event === "theme") {
      paint(message.data);
      return;
    }
    const settle = waiting.get(message.id);
    if (!settle) return;
    waiting.delete(message.id);
    settle(message.result);
  });

  const id = ++next;
  waiting.set(id, paint);
  // A page that never says hello is replaced by the window's "didn't
  // answer" card; saying it is also how the theme is asked for.
  parent.postMessage({ magpie: 1, id, method: "hello" }, "*");
})();
