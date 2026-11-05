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
  location.replace(target.href);
})().catch((error) => {
  document.body.textContent = String(error?.message || error);
});
