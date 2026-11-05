import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HTML = fs.readFileSync(path.join(ROOT, "page", "ui.html"), "utf8");
const JS = fs.readFileSync(path.join(ROOT, "page", "ui.js"), "utf8");
const CSS = fs.readFileSync(path.join(ROOT, "page", "ui.css"), "utf8");
const INDEX = fs.readFileSync(path.join(ROOT, "page", "index.html"), "utf8");
const APP = fs.readFileSync(path.join(ROOT, "page", "app.js"), "utf8");

const LANGS = ["en", "zh", "zh-TW", "ja", "de"];

function dictBlock() {
  const start = JS.indexOf("const ADMIN_MESSAGES = {");
  const end = JS.indexOf("const adminDict", start);
  assert.ok(start >= 0 && end > start, "the administration dictionary should be in ui.js");
  return JS.slice(start, end);
}

function keysOf(block, language) {
  const marker = language === "zh-TW" ? '\n  "zh-TW": {' : `\n  ${language}: {`;
  const start = block.indexOf(marker);
  assert.ok(start >= 0, `the ${language} dictionary should be present`);
  const next = LANGS
    .map((candidate) => {
      const at = block.indexOf(candidate === "zh-TW" ? '\n  "zh-TW": {' : `\n  ${candidate}: {`, start + 1);
      return at;
    })
    .filter((at) => at > start)
    .sort((a, b) => a - b)[0];
  const sub = block.slice(start, next ?? block.length);
  return new Set([...sub.matchAll(/^\s{4}([A-Za-z0-9_]+):/gm)].map((match) => match[1]));
}

test("every administration string exists in all five languages", () => {
  const block = dictBlock();
  const used = new Set([...JS.matchAll(/\bta\("([A-Za-z0-9_]+)"/g)].map((match) => match[1]));
  assert.ok(used.size > 80, "the page should use its administration dictionary");
  for (const language of LANGS) {
    const keys = keysOf(block, language);
    const missing = [...used].filter((key) => !keys.has(key));
    assert.deepEqual(missing, [], `${language} is missing ${missing.join(", ")}`);
  }
});

test("every id the administration translator touches exists in the page", () => {
  const translate = JS.slice(JS.indexOf("function translateAdmin("), JS.indexOf("\n}\n", JS.indexOf("function translateAdmin(")));
  const ids = new Set([...translate.matchAll(/\$\("([A-Za-z0-9_]+)"\)/g)].map((match) => match[1]));
  assert.ok(ids.size > 10);
  for (const id of ids) {
    assert.match(HTML, new RegExp(`id="${id}"`), `ui.html should contain #${id}`);
  }
});

test("the gateway page carries a device list and a provider key list", () => {
  for (const id of ["gwDevicesTitle", "gwDevicesCount", "gwDevices", "gwDevicesEmpty"]) {
    assert.match(HTML, new RegExp(`id="${id}"`));
  }
  assert.match(JS, /adminApi\("\/devices"\)/);
  assert.match(JS, /function deviceRow\(/);
  assert.match(JS, /function providerKeyRow\(/);
  assert.match(CSS, /\.key-row/);
});

test("each administration form asks for an audit reason", () => {
  for (const id of ["providerForm", "groupForm", "keyForm", "keyEditForm"]) {
    const start = HTML.indexOf(`id="${id}"`);
    assert.ok(start > 0, `${id} should exist`);
    const end = HTML.indexOf("</form>", start);
    const form = HTML.slice(start, end);
    assert.match(form, /name="reason"/, `${id} should carry an audit reason`);
  }
});

test("the provider form can add keys without ever reading one back", () => {
  assert.match(HTML, /<form id="providerForm"[\s\S]*name="addKeys"/);
  const save = JS.slice(JS.indexOf("async function saveProvider("), JS.indexOf("async function deleteProvider("));
  assert.match(save, /body\.addKeys = addKeys/);
  assert.match(save, /expectedRevision: editingProvider\.revision/);
  const patch = JS.slice(JS.indexOf("async function patchProviderKey("), JS.indexOf("// providerKeyLine says"));
  assert.match(patch, /keys: \[change\]/);
  assert.match(patch, /reason/);
});

test("administrator mode hides the employee sync action and restores it", () => {
  assert.match(JS, /syncButton\.hidden = admin;/);
  assert.match(JS, /syncButton\.hidden = false|syncButton\.hidden = admin;/);
  assert.match(JS, /function setView\(name\)/);
});

test("the page never embeds the management console in a frame", () => {
  assert.ok(!/iframe/i.test(HTML), "the native page must not use an iframe");
  assert.match(JS, /window\.open\(consoleUrl, "_blank", "noopener,noreferrer"\)/);
});

test("a route detail shows every attempt and its source", () => {
  const render = JS.slice(JS.indexOf("function renderRouteDetail("), JS.indexOf("function parseLimit("));
  // The management service names the list `attempts`, from a live trace
  // or from the usage ledger; the page must read that, not a count.
  assert.match(render, /route\.attempts/);
  assert.match(render, /route\.source/);
  assert.match(render, /ta\("detailTries"/);
  assert.match(render, /detailGroup/);
});

test("the page takes the window's look, not a palette of its own", () => {
  // The page is drawn by the plugin's service, another origin, so it cannot
  // read the window's stylesheet. index.html (which the window serves) hands
  // the theme's tokens to the service, which writes them out as theme.css;
  // ui.css reads them. A palette of the page's own would drift from the
  // window the moment either theme changes.
  assert.match(INDEX, /<script src="_magpie\/bridge\.js"><\/script>/);
  assert.match(APP, /magpie\.theme\?\.tokens/);
  assert.match(APP, /searchParams\.set\("tokens"/);
  assert.match(HTML, /href="theme\.css"/);
  assert.ok(
    HTML.indexOf('href="theme.css"') < HTML.indexOf('href="ui.css"'),
    "the window's tokens load before the page's own rules",
  );
  assert.doesNotMatch(HTML, /_magpie\/bridge\.js/, "the service cannot serve the window's bridge");
  // The page still talks to its parent: hello asks for the theme, and a
  // theme event repaints an open page when the reader switches light/dark.
  assert.match(HTML, /<script src="theme-bridge\.js"><\/script>/);
  assert.ok(
    HTML.indexOf('src="theme-bridge.js"') < HTML.indexOf('src="ui.js"'),
    "the theme bridge loads before the page's script",
  );
  const BRIDGE = fs.readFileSync(path.join(ROOT, "page", "theme-bridge.js"), "utf8");
  assert.match(BRIDGE, /method: "hello"/);
  assert.match(BRIDGE, /message\.event === "theme"/);
  assert.match(BRIDGE, /--magpie-/);
  for (const token of ["--magpie-bg", "--magpie-card", "--magpie-fg", "--magpie-line",
    "--magpie-accent", "--magpie-muted", "--magpie-font"]) {
    assert.match(CSS, new RegExp(`var\\(${token}`), `ui.css should read ${token}`);
  }
  assert.doesNotMatch(CSS, /html\[data-theme="dark"\]/, "the page keeps no dark palette");
  assert.doesNotMatch(CSS, /#f6f5f1|#171816/, "the old cream palette should be gone");
});

test("the resources tab reads the catalog and each device's sync report", () => {
  // The tab shows what an administrator can read in the client: the
  // published catalog and the last sync report per device. Publishing and
  // rollback are not here, so the page must not promise them.
  for (const id of ["resTitle", "resCount", "resList", "resEmpty",
    "resDetail", "resDetailTitle", "resReleases", "resReleasesEmpty",
    "syncTitle", "syncCount", "syncList", "syncEmpty"]) {
    assert.match(HTML, new RegExp(`id="${id}"`), `ui.html should contain #${id}`);
  }
  assert.match(HTML, /data-tab="resources"/);
  assert.match(JS, /adminApi\("\/resources"\)/);
  assert.match(JS, /adminApi\("\/resource-sync\/reports"\)/);
  assert.match(JS, /function catalogResourceRow\(/);
  assert.match(JS, /function syncReportRow\(/);
  // A resource's row opens its releases; the detail reads one resource,
  // never the whole catalog again.
  assert.match(JS, /function openResource\(/);
  assert.match(JS, /adminApi\(`\/resources\/\$\{encodeURIComponent\(resource\.id\)\}`\)/);
  assert.match(JS, /function releaseRow\(/);
});

test("an attempt row names what served it, not just the route", () => {
  const render = JS.slice(JS.indexOf("function renderRouteDetail("), JS.indexOf("function parseLimit("));
  assert.match(render, /item\.served \|\| item\.upstream/);
  assert.match(render, /item\.millis/);
  const request = JS.slice(JS.indexOf("function requestRow("), JS.indexOf("function renderProviders("));
  assert.match(request, /row\.callerKeyName/);
  assert.match(request, /row\.account/);
});
