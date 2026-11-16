(async () => {
  await magpie.ready;
  let service = magpie.service;
  if (!service) {
    let port = 3477;
    try {
      const options = await magpie.options.get();
      if (Number(options?.port)) port = Number(options.port);
    } catch {
      // the package's own port is the fallback
    }
    service = `http://127.0.0.1:${port}/`;
  }
  const target = new URL(service);
  target.searchParams.set("lang", magpie.theme?.lang || "en");
  target.searchParams.set("theme", magpie.theme?.dark ? "dark" : "light");
  // The page is drawn by the service, another origin, so it cannot read the
  // window's stylesheet. Hand it the theme's tokens here: the service turns
  // them into theme.css, and the page takes the window's colours and font.
  const tokens = magpie.theme?.tokens;
  if (tokens && typeof tokens === "object") {
    try {
      target.searchParams.set("tokens", JSON.stringify(tokens));
    } catch {
      // a theme that cannot be written costs the page its colours, not its life
    }
  }
  location.replace(target.href);
})().catch((error) => {
  document.body.textContent = String(error?.message || error);
});
