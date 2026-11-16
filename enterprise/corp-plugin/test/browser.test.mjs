// openBrowser hands a URL to this computer's browser.
//
// The Windows path goes through cmd, which reads an unquoted "&" as the
// end of the command: a sign-in page's query string would arrive cut in
// half. The URL must reach the browser as one quoted argument.
import test from "node:test";
import assert from "node:assert/strict";

import { openBrowser } from "../src/auth.mjs";

function fakeSpawn() {
  const calls = [];
  const spawnFn = (command, args, options) => {
    calls.push({ command, args, options });
    return { unref() {} };
  };
  return { calls, spawnFn };
}

test("a Windows browser is handed the whole URL, query string and all", () => {
  const { calls, spawnFn } = fakeSpawn();
  const url = "https://copilot.tencent.com/login?platform=workbuddy&state=abc-123";
  assert.equal(openBrowser(url, { platform: "win32", spawnFn }), true);
  assert.equal(calls[0].command, "cmd");
  assert.deepEqual(calls[0].args, ["/c", "start", "", `"${url}"`]);
  assert.equal(calls[0].options.windowsVerbatimArguments, true);
  assert.equal(calls[0].options.detached, true);
});

test("macOS and Linux are given the URL as one argument too", () => {
  for (const [platform, command] of [["darwin", "open"], ["linux", "xdg-open"]]) {
    const { calls, spawnFn } = fakeSpawn();
    const url = "https://www.workbuddy.ai/login?platform=workbuddy&state=abc-123";
    assert.equal(openBrowser(url, { platform, spawnFn }), true);
    assert.equal(calls[0].command, command);
    assert.deepEqual(calls[0].args, [url]);
  }
});

test("a machine that can't start a browser says so, rather than throwing", () => {
  const spawnFn = () => {
    throw new Error("no browser here");
  };
  assert.equal(openBrowser("https://example.com/login?a=1&b=2", { platform: "win32", spawnFn }), false);
});
