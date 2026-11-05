import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HTML = fs.readFileSync(path.join(ROOT, "page", "ui.html"), "utf8");
const JS = fs.readFileSync(path.join(ROOT, "page", "ui.js"), "utf8");
const CSS = fs.readFileSync(path.join(ROOT, "page", "ui.css"), "utf8");

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

test("an attempt row names what served it, not just the route", () => {
  const render = JS.slice(JS.indexOf("function renderRouteDetail("), JS.indexOf("function parseLimit("));
  assert.match(render, /item\.served \|\| item\.upstream/);
  assert.match(render, /item\.millis/);
  const request = JS.slice(JS.indexOf("function requestRow("), JS.indexOf("function renderProviders("));
  assert.match(request, /row\.callerKeyName/);
  assert.match(request, /row\.account/);
});
