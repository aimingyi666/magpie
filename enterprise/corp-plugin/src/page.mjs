// The plugin's page: what an employee sees, and — for an administrator —
// what this computer's magpie shares through the corporate gateway.
//
// Everything is drawn here, from JSON the loopback service answers. No
// server word is interpolated into the script, and no key or device token
// reaches the page: the status it starts with holds names and counts only.

const STYLE = `
:root{
  color-scheme:light dark;
  --bg:#f4f4f6;--card:#ffffff;--card-2:#f9f9fb;--pill:#f1f1f4;--pill-hover:#e9e9ee;
  --line:#e3e3e8;--line-2:#ececf0;--fg:#1c1c21;--fg-2:#4b4b53;--muted:#85858d;--faint:#b9b9c2;
  --accent:#4f46e5;--accent-soft:#eeedfd;--accent-fg:#ffffff;
  --ok:#189a58;--ok-soft:#e4f6ec;--warn:#b45309;--warn-soft:#fbf0df;
  --err:#d64545;--err-soft:#fbe9e9;
  --font:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI","Microsoft YaHei UI","Microsoft YaHei",system-ui,sans-serif;
  --code:ui-monospace,"SF Mono","Cascadia Mono",Consolas,"Microsoft YaHei UI",monospace;
  --shadow:0 1px 2px rgba(20,22,30,.04);
  --thumb:0 1px 2px rgba(0,0,0,.14),0 0 0 .5px rgba(0,0,0,.08);
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    color-scheme:dark;
    --bg:#1a1a1e;--card:#232327;--card-2:#1f1f23;--pill:#2d2d33;--pill-hover:#36363d;
    --line:#333339;--line-2:#2c2c32;--fg:#ededf1;--fg-2:#b9b9c1;--muted:#8b8b94;--faint:#56565f;
    --accent:#a5b4fc;--accent-soft:#2b2c47;--accent-fg:#14142a;
    --ok:#6fd99b;--ok-soft:#1e3a2b;--warn:#f2b544;--warn-soft:#3f3220;--err:#f28b82;--err-soft:#45272a;
    --shadow:none;--thumb:inset 0 .5px 0 rgba(255,255,255,.08),0 1px 2px rgba(0,0,0,.3);
  }
}
:root[data-theme="dark"]{
  color-scheme:dark;
  --bg:#1a1a1e;--card:#232327;--card-2:#1f1f23;--pill:#2d2d33;--pill-hover:#36363d;
  --line:#333339;--line-2:#2c2c32;--fg:#ededf1;--fg-2:#b9b9c1;--muted:#8b8b94;--faint:#56565f;
  --accent:#a5b4fc;--accent-soft:#2b2c47;--accent-fg:#14142a;
  --ok:#6fd99b;--ok-soft:#1e3a2b;--warn:#f2b544;--warn-soft:#3f3220;--err:#f28b82;--err-soft:#45272a;
  --shadow:none;--thumb:inset 0 .5px 0 rgba(255,255,255,.08),0 1px 2px rgba(0,0,0,.3);
}
:root[data-theme="light"]{color-scheme:light only}
*{box-sizing:border-box}
[hidden]{display:none !important}
html{background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--fg);font:400 13px/1.4 var(--font);-webkit-font-smoothing:antialiased}
code{font:11px var(--code);color:var(--fg-2)}
.wrap{max-width:1000px;margin:0 auto;padding:18px 20px 44px}
header.top{display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.brand{display:flex;gap:10px;align-items:center;min-width:0}
.logo{width:30px;height:30px;border-radius:8px;background:var(--pill);box-shadow:inset 0 0 0 1px var(--line);color:var(--fg-2);display:grid;place-items:center;font-weight:600;font-size:13px;flex:none}
h1{font-size:15px;line-height:1.25;margin:0;font-weight:600;letter-spacing:-.005em}
h2{font-size:11px;margin:0;font-weight:600;letter-spacing:.05em;color:var(--muted)}
h3{font-size:11px;margin:0 0 3px;color:var(--muted);font-weight:600;letter-spacing:.05em;text-transform:uppercase}
.sub{margin:2px 0 0;color:var(--muted);font-size:11.5px;overflow-wrap:anywhere}
.tabs{display:flex;gap:2px;padding:2px;border-radius:8px}
.tab{font:inherit;font-size:12.5px;border:0;background:transparent;color:var(--muted);height:26px;padding:0 12px;border-radius:6px;cursor:pointer;font-weight:500;display:inline-flex;align-items:center;transition:color .15s,background .15s}
.tab.is-on{background:var(--card);color:var(--fg);box-shadow:var(--thumb)}
.tab:hover:not(.is-on){color:var(--fg-2)}
.tab:disabled{opacity:.45;cursor:default}
a.tab{text-decoration:none;color:var(--muted)}
a.tab.is-on{color:var(--fg)}
button{font:inherit}
.btn{display:inline-flex;align-items:center;justify-content:center;height:27px;padding:0 10px;border:1px solid var(--line);background:var(--card);color:var(--fg-2);border-radius:7px;cursor:pointer;font-size:12px;font-weight:500;white-space:nowrap;text-decoration:none;box-shadow:0 1px 1px rgba(0,0,0,.04);transition:background .12s,border-color .12s,color .12s}
.btn:hover:not(:disabled){border-color:var(--muted);background:var(--card-2);color:var(--fg)}
.btn:disabled{opacity:.5;cursor:default}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-fg);font-weight:500}
.btn.primary:hover:not(:disabled){background:var(--accent);color:var(--accent-fg);filter:brightness(1.08)}
.btn.danger{color:var(--err);border-color:color-mix(in srgb,var(--err) 35%,var(--line))}
.btn.danger:hover:not(:disabled){color:var(--err);background:var(--err-soft);border-color:color-mix(in srgb,var(--err) 45%,var(--line))}
.btn.sm{height:22px;padding:0 8px;font-size:11.5px;border-radius:6px}
.link{border:0;background:transparent;color:var(--accent);cursor:pointer;font-weight:500;font-size:12px;padding:3px 7px;border-radius:6px;text-decoration:none}
.link:hover{background:var(--pill)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.banner{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);background:var(--card);border-radius:10px;padding:9px 12px;margin:0 0 12px;color:var(--muted);font-size:12.5px}
.banner.error{border-color:color-mix(in srgb,var(--err) 35%,var(--line));background:var(--err-soft);color:var(--err)}
.banner.ok{border-color:color-mix(in srgb,var(--ok) 35%,var(--line));background:var(--ok-soft);color:var(--ok)}
.banner.warn{border-color:color-mix(in srgb,var(--warn) 35%,var(--line));background:var(--warn-soft);color:var(--warn)}
.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:10px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-bottom:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;min-width:0;margin-bottom:10px}
.cards .card,.grid .card{margin-bottom:0}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:8px;min-height:18px}
.big{font-size:20px;font-weight:600;letter-spacing:-.01em;font-variant-numeric:tabular-nums;line-height:1.15;margin:2px 0 4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.muted{color:var(--muted)}
.small{font-size:12px}
.row{display:flex;justify-content:space-between;gap:12px;padding:3px 0;font-size:12.5px}
.row span:first-child{color:var(--muted);flex:none}
.row strong{font-weight:500;color:var(--fg-2);text-align:right;overflow-wrap:anywhere}
.pill{display:inline-flex;align-items:center;gap:5px;border-radius:5px;padding:1px 6px;font-size:10.5px;font-weight:600;letter-spacing:.02em;background:var(--pill);color:var(--muted);white-space:nowrap}
.pill.ok{background:var(--ok-soft);color:var(--ok)}
.pill.warn{background:var(--warn-soft);color:var(--warn)}
.pill.err{background:var(--err-soft);color:var(--err)}
.pill.accent{background:var(--accent-soft);color:var(--accent)}
.dot{width:6px;height:6px;border-radius:50%;background:currentColor;display:inline-block;flex:none}
.chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
.chip{background:var(--pill);border-radius:5px;padding:1px 6px;font:10.5px var(--code);color:var(--muted);max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.list{display:flex;flex-direction:column;min-width:0}
.item{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;border-top:1px solid var(--line-2);padding:9px 0;background:none;min-width:0}
.item[data-mark]::before{content:attr(data-mark);flex:none;width:28px;height:28px;border-radius:7px;background:var(--pill);box-shadow:inset 0 0 0 1px var(--line-2);color:var(--fg-2);display:grid;place-items:center;font-size:11.5px;font-weight:600;margin-top:1px}
.item:first-child{border-top:0;padding-top:2px}
.item:last-child{padding-bottom:2px}
.item-main{min-width:0;flex:1 1 auto}
.item-title{font-weight:500;font-size:12.5px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;overflow-wrap:anywhere}
.item-sub{color:var(--muted);font-size:11.5px;margin-top:1px;overflow-wrap:anywhere}
.item-side{flex:none;text-align:right;align-self:center}
.empty{padding:22px 12px;text-align:center;color:var(--muted);font-size:12px;line-height:1.5}
.resources{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
.res-col{min-width:0}
.res-col ul{margin:4px 0 0;padding-left:16px}
.res-col li{margin:1px 0;font-size:12.5px;overflow-wrap:anywhere}
.res-col li::marker{color:var(--faint)}
.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:14px}
.field{display:flex;flex-direction:column;gap:5px;margin:8px 0;font-size:11.5px;color:var(--muted)}
.field input,.field select{font:inherit;font-size:12.5px;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:7px;height:28px;padding:0 8px;min-width:0}
.field input::placeholder{color:var(--muted);opacity:.75}
.check{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--fg);margin:6px 12px 0 0;cursor:pointer}
.check input{accent-color:var(--accent)}
.demo{display:none;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px;padding:10px 12px;border:1px solid var(--line-2);border-radius:10px;background:var(--card-2)}
.demo.on{display:flex}
.demo input{font:inherit;font-size:12.5px;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:7px;height:28px;padding:0 8px;min-width:210px}
.gate{max-width:640px}
.gate h2{font-size:13.5px;color:var(--fg);letter-spacing:0;text-transform:none;margin-bottom:6px}
.gate code{background:var(--pill);padding:1px 5px;border-radius:4px}
.person{border-top:1px solid var(--line-2);padding:12px 0}
.person:first-child{border-top:0;padding-top:2px}
.person-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap}
.who{display:flex;gap:10px;align-items:center;min-width:0}
.avatar{width:28px;height:28px;border-radius:7px;background:var(--pill);color:var(--fg-2);box-shadow:inset 0 0 0 1px var(--line-2);display:grid;place-items:center;font-weight:600;font-size:12px;flex:none}
.device{border-top:1px solid var(--line);margin-top:10px;padding-top:10px}
.device-head{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap}
.device-head strong{font-weight:500;color:var(--fg)}
.edit{display:grid;grid-template-columns:minmax(0,1fr) 130px 130px;gap:8px;align-items:end;margin-top:8px}
.edit .field{margin:0}
.edit-wide{grid-column:1/-1}
.toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);background:var(--fg);color:var(--bg);padding:8px 14px;border-radius:8px;font-size:12.5px;box-shadow:0 10px 30px rgba(0,0,0,.25);max-width:min(90vw,620px);z-index:9}
.toast.error{background:var(--err);color:#fff}
.wb-url{display:block;margin-top:8px;padding:6px 8px;border:1px solid var(--line);border-radius:7px;background:var(--card-2);font:11px var(--code);color:var(--fg-2);overflow-wrap:anywhere}
.hidden{display:none !important}

/* The sign-in page is its own screen: no navigation, one card. */
.auth-body{display:grid;place-items:center;min-height:100vh}
.auth-body .wrap{max-width:420px;padding:28px 18px 40px}
.auth{display:flex;flex-direction:column;gap:12px}
.auth .card{padding:24px 24px 20px}
.auth .logo{width:38px;height:38px;border-radius:10px;font-size:16px;margin-bottom:14px}
.auth h1{font-size:18px;margin:0 0 6px}
.auth .field{margin-top:14px}
.auth .btn.primary{width:100%;height:34px;font-size:13px;margin-top:16px}
.auth .btn{width:100%}
.auth .demo{display:none;margin-top:14px;flex-wrap:wrap}
.auth .demo.on{display:flex}
.auth .demo input{flex:1 1 100%;min-width:0}
.auth .demo .btn{width:auto;flex:1 1 0}
.auth-note{text-align:center;margin:2px 0 0}

/* The personal page. */
.profile-head{display:flex;justify-content:space-between;gap:14px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.profile-head h2{font-size:17px;color:var(--fg);letter-spacing:0;text-transform:none;font-weight:600}
.avatar.lg{width:42px;height:42px;font-size:17px;border-radius:10px}
.facts{margin-top:8px;border-top:1px solid var(--line-2);padding-top:6px}
@media (max-width:860px){
  .cards,.grid,.resources{grid-template-columns:1fr}
  .edit{grid-template-columns:1fr 1fr}
  .wrap{padding:16px 14px 34px}
}
`;

const SCRIPT = `
var TOKEN = window.__CORP_TOKEN;
var INITIAL = window.__CORP_STATUS;
var PAGE = window.__CORP_PAGE || "overview";
var state = { status: INITIAL, session: null, people: null, selected: {}, share: null, importing: false };

function on(id, type, handler){
  var el = document.getElementById(id);
  if (el) el.addEventListener(type, handler);
}

function esc(value){
  return String(value === undefined || value === null ? "" : value).replace(/[&<>"']/g, function(c){
    return ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c];
  });
}
function text(value){ return (value === undefined || value === null || value === "") ? "—" : String(value); }
function count(value){ return Number(value || 0).toLocaleString(); }
function markOf(value){
  var s = String(value === undefined || value === null ? "" : value).trim();
  return s ? s.slice(0, 1).toUpperCase() : "企";
}
function when(value){
  if (!value) return "—";
  var at = new Date(value);
  return isNaN(at.getTime()) ? String(value) : at.toLocaleString();
}
// lastUploadAt is kept by channel (usage, masking, sessions); the page
// shows the most recent one, not the map itself.
function lastUpload(value){
  if (!value) return "—";
  if (typeof value === "string") return when(value);
  var latest = 0;
  if (typeof value === "object"){
    Object.keys(value).forEach(function(channel){
      var at = Date.parse(value[channel]);
      if (Number.isFinite(at) && at > latest) latest = at;
    });
  }
  return latest ? when(new Date(latest).toISOString()) : "—";
}
function modeLabel(mode){
  if (mode === "native") return "原生供应商";
  if (mode === "remote") return "Remote magpie";
  if (mode === "off") return "已停止分享";
  return "未设置";
}
function api(path, options){
  options = options || {};
  var init = { method: options.method || "GET", headers: { "x-page-token": TOKEN } };
  if (options.body !== undefined){
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  return fetch(path, init).then(function(response){
    return response.json().catch(function(){ return {}; }).then(function(body){
      return { ok: response.ok, status: response.status, body: body };
    });
  }).catch(function(error){
    return { ok: false, status: 0, body: { error: { message: String(error && error.message || error) } } };
  });
}
function messageOf(result, fallback){
  return (result && result.body && result.body.error && result.body.error.message) || fallback;
}
function toast(message, kind){
  var el = document.getElementById("toast");
  el.textContent = message;
  el.className = "toast" + (kind === "error" ? " error" : "");
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(function(){ el.hidden = true; }, kind === "error" ? 6000 : 3200);
}
// safeUrl keeps a link to the web: a sign-in page is an http(s) address,
// never a javascript: one a compromised gateway could put in its answer.
function safeUrl(value){
  var raw = String(value || "").trim();
  if (!raw) return "";
  try {
    var url = new URL(raw);
    return url.protocol === "https:" || url.protocol === "http:" ? raw : "";
  } catch (e) {
    return "";
  }
}
function banner(message, kind){
  var el = document.getElementById("banner");
  if (!el) return;
  if (!message){ el.hidden = true; el.textContent = ""; return; }
  el.hidden = false;
  el.className = "banner " + (kind || "");
  el.textContent = message;
}
function chips(list, limit){
  var items = Array.isArray(list) ? list : [];
  var shown = items.slice(0, limit || 8).map(function(item){
    return '<span class="chip" title="' + esc(item) + '">' + esc(item) + '</span>';
  }).join("");
  if (items.length > (limit || 8)) shown += '<span class="chip">+' + (items.length - (limit || 8)) + '</span>';
  return shown;
}
function resourceColumns(resources){
  resources = resources || {};
  return [["指令", resources.instructions], ["MCP 服务", resources.mcp], ["技能", resources.skills]]
    .map(function(pair){
      var list = Array.isArray(pair[1]) ? pair[1] : [];
      return '<div class="res-col"><h3>' + esc(pair[0]) + ' · ' + count(list.length) + '</h3><ul>' +
        (list.length ? list.map(function(item){ return '<li>' + esc(item) + '</li>'; }).join("") : '<li class="muted">暂无</li>') +
        '</ul></div>';
    }).join("");
}

function drawUser(s){
  if (!document.getElementById("userAccount")) return;
  state.status = s;
  var device = s.device || {};
  var role = s.role || device.role || "member";
  document.getElementById("userAccount").innerHTML =
    '<div class="big">' + esc(device.enrolled ? (device.name || device.email || "已登录") : "未登录") + '</div>' +
    '<div class="item-sub">' + esc(device.enrolled ? (device.email || "") : "登录后从企业网关领取密钥") + '</div>' +
    '<div class="chips">' +
      '<span class="pill ' + (device.enrolled && device.usable ? "ok" : "warn") + '"><span class="dot"></span>' +
        (device.enrolled ? (device.usable ? "登录有效" : "登录已过期") : "未登录") + '</span>' +
      (role === "admin" ? '<span class="pill accent">管理员</span>' : "") +
      (device.expiresAt ? '<span class="chip">到期 ' + esc(when(device.expiresAt)) + '</span>' : "") +
    '</div>';

  var models = (s.providers || []).reduce(function(total, provider){ return total + Number(provider.models || 0); }, 0);
  document.getElementById("userGateway").innerHTML =
    '<div class="big">' + count((s.providers || []).length) + ' <span class="muted" style="font-size:12px;font-weight:500">个供应商</span></div>' +
    '<div class="row"><span>网关地址</span><strong>' + esc(text(device.gateway || s.baseUrl)) + '</strong></div>' +
    '<div class="row"><span>模型</span><strong>' + count(models) + '</strong></div>' +
    '<div class="row"><span>分享模式</span><strong>' + esc(modeLabel(s.sharing && s.sharing.mode)) + '</strong></div>';

  document.getElementById("userSync").innerHTML =
    '<div class="big">' + esc(s.lastSyncAt ? when(s.lastSyncAt) : "从未同步") + '</div>' +
    '<div class="row"><span>资源版本</span><strong>' + esc(s.revision || "—") + '</strong></div>' +
    '<div class="row"><span>上传</span><strong>' + (s.upload && (s.upload.usage || s.upload.masking) ? "已开启" : "关闭") + '</strong></div>' +
    '<div class="row"><span>上次错误</span><strong>' + esc(s.lastSyncError || "无") + '</strong></div>';

  var providers = document.getElementById("userProviders");
  providers.innerHTML = (s.providers || []).length
    ? (s.providers || []).map(function(provider){
        return '<div class="item" data-mark="' + esc(markOf(provider.id || provider.name)) + '"><div class="item-main">' +
          '<div class="item-title"><code>' + esc(provider.id) + '</code> ' + esc(provider.name) + '</div>' +
          '<div class="item-sub">' + count(provider.models) + ' 个模型</div></div>' +
          '<div class="item-side"><span class="pill ok">已启用</span></div></div>';
      }).join("")
    : '<div class="empty">还没有同步到企业供应商。登录后点「立即同步」。</div>';

  var sources = (s.sharing && s.sharing.sources) || [];
  document.getElementById("userSources").innerHTML = sources.length
    ? sources.map(function(source){
        return '<div class="item" data-mark="' + esc(markOf(source.name || source.id)) + '"><div class="item-main"><div class="item-title">' + esc(source.name) + '</div>' +
          '<div class="item-sub"><code>' + esc(source.id) + '</code> · ' + count(source.models) + ' 个模型</div></div></div>';
      }).join("")
    : '<div class="empty">' + (s.sharing && s.sharing.mode === "off"
        ? "企业已停止分享供应商。"
        : "这次分享没有列出具体来源；管理员可在「管理员」页选择要分享的供应商。") + '</div>';

  // Plugins the corporation names for this device. The page shows what was
  // asked for and whether this machine has applied it; installing happens
  // in the magpie process, not here.
  var plugins = s.plugins || [];
  var appliedPlugins = Array.isArray(s.appliedPlugins) ? s.appliedPlugins : [];
  document.getElementById("userPluginsCard").hidden = !plugins.length;
  document.getElementById("userPlugins").innerHTML = plugins.map(function(plugin){
    var applied = appliedPlugins.indexOf(plugin.id) !== -1;
    return '<div class="item" data-mark="' + esc(markOf(plugin.name || plugin.id)) + '"><div class="item-main">' +
      '<div class="item-title">' + esc(plugin.name || plugin.id) + ' <span class="chip">' + esc(plugin.id) + '</span></div>' +
      '<div class="item-sub">' + (plugin.model ? '接入 <code>' + esc(plugin.model) + '</code>' : '接入企业网关') + '</div></div>' +
      '<div class="item-side"><span class="pill ' + (applied ? 'ok' : 'warn') + '">' +
        (applied ? '已安装' : '待安装') + '</span></div></div>';
  }).join("");

  var resources = s.resources || { instructions: [], mcp: [], skills: [] };
  document.getElementById("userResources").innerHTML = resourceColumns(resources);

  if (!s.configured) banner("请先在插件设置里填写企业服务端地址，然后登录。", "warn");
  else if (s.lastSyncError) banner("上次同步失败：" + s.lastSyncError, "error");
  else banner("");

  var demo = document.getElementById("demoBox");
  if (demo) demo.className = s.demoSignIn ? "demo on" : "demo";
  wbDraw();
}

// ---- sharing this employee's own WorkBuddy account ---------------------
//
// The local service opens the vendor's page in this computer's browser (the
// sandboxed frame can't); the token stays in the gateway's plugin. This page
// holds an id and a URL and polls until the account is
// imported, then syncs once so the new models show up here too.

var WB_PROVIDERS = [
  { id: "workbuddy", label: "国内版 WorkBuddy", primary: true },
  { id: "workbuddy-ai", label: "国际版 WorkBuddy", primary: false }
];

function wbStateLabel(value){
  if (value === "done") return "已导入企业供应商";
  if (value === "failed") return "登录失败";
  if (value === "canceled") return "已取消";
  return "等待扫码登录";
}

// wbLocalItems are the WorkBuddy accounts this computer's magpie already
// has signed in. The status holds their names only; the tokens stay in the
// service until one is imported.
function wbLocalItems(){
  var local = state.status && Array.isArray(state.status.localWorkbuddy) ? state.status.localWorkbuddy : [];
  return local.filter(function(item){ return item && item.provider; });
}

// wbLocalHtml offers each of them for import: the sign-in moves to the
// corporate gateway and this magpie signs out of it, so one token is
// renewed in one place.
function wbLocalHtml(){
  var items = wbLocalItems();
  if (!items.length) return "";
  return '<div class="list">' + items.map(function(item, index){
    var label = text(item.account) || "WorkBuddy 账号";
    if (item.provider === "workbuddy-ai") label += "（国际版）";
    return '<div class="item" data-mark="' + esc(markOf(label)) + '"><div class="item-main">' +
      '<div class="item-title">' + esc(label) + '</div>' +
      '<div class="item-sub">本机 magpie 已登录。导入后企业网关使用这份登录，本机退出这个账号。</div>' +
      '</div><div class="item-side">' +
      '<button class="btn" type="button" data-wb-local="' + index + '"' + (state.importing ? ' disabled' : '') +
      '>导入</button></div></div>';
  }).join("") + '</div>';
}

function wbBindLocal(){
  var buttons = document.querySelectorAll("[data-wb-local]");
  for (var i = 0; i < buttons.length; i++){
    buttons[i].addEventListener("click", function(){
      wbImport(Number(this.getAttribute("data-wb-local")));
    });
  }
}

function wbDraw(){
  var card = document.getElementById("userWorkbuddy");
  if (!card) return;
  var enrolled = !!(state.status && state.status.device && state.status.device.enrolled);
  var share = state.share;
  var busy = !!(share && share.state === "waiting");
  var local = wbLocalHtml();
  var buttons = document.getElementById("wbButtons");
  buttons.innerHTML = WB_PROVIDERS.map(function(provider){
    return '<button class="btn' + (provider.primary ? ' primary' : '') + '" type="button" data-share="' +
      esc(provider.id) + '"' + (busy || !enrolled ? ' disabled' : '') + '>共享' + esc(provider.label) + '</button>';
  }).join("");
  for (var i = 0; i < buttons.children.length; i++){
    buttons.children[i].addEventListener("click", function(){
      wbStart(this.getAttribute("data-share"));
    });
  }

  var detail = document.getElementById("wbDetail");
  if (!enrolled){
    detail.innerHTML = '<div class="empty">先完成「企业登录」，再共享你的 WorkBuddy 账号。</div>';
    return;
  }
  if (!share){
    detail.innerHTML = local +
      '<div class="empty">还没有共享记录。点上面的按钮扫码登录，或直接导入本机 magpie 已登录的账号；' +
      '账号会导入企业网关，管理员勾选要下发的模型后，同事就能用。</div>';
    wbBindLocal();
    return;
  }
  var html = '<div class="list"><div class="item" data-mark="' + esc(markOf(share.providerName || share.provider)) + '"><div class="item-main">' +
    '<div class="item-title">' + esc(share.providerName || share.provider) + '</div>' +
    '<div class="item-sub">' + esc(wbStateLabel(share.state)) + '</div>' +
    '</div>' +
    '<div class="item-side"><span class="pill ' +
      (share.state === "done" ? "ok" : share.state === "failed" ? "err" : share.state === "waiting" ? "warn" : "") +
      '">' + esc(wbStateLabel(share.state)) + '</span></div></div>' +
    '<div class="row"><span>账号</span><strong>' + esc(text(share.account)) + '</strong></div>' +
    '<div class="row"><span>模型</span><strong>' + count((share.models || []).length) + '</strong></div>' +
    '<div class="row"><span>更新</span><strong>' + esc(when(share.updatedAt || share.createdAt)) + '</strong></div>';
  if ((share.models || []).length) html += '<div class="chips">' + chips(share.models, 12) + '</div>';
  if (share.error) html += '<div class="item-sub">' + esc(share.error) + '</div>';
  if (share.state === "waiting"){
    var link = safeUrl(share.url);
    html += link
      ? '<div class="item-sub">在浏览器打开下面的登录页扫码；窗口没自动打开时，点一下地址再复制。</div>' +
        '<a class="wb-url" id="wbUrl" href="' + esc(link) + '" target="_blank" rel="noreferrer noopener">' +
        esc(link) + '</a>'
      : '<div class="item-sub">正在等待浏览器登录；如果窗口没有打开，请取消后重试。</div>';
    html += '<div class="actions"><button class="btn danger" type="button" id="wbCancel">取消共享</button></div>';
  } else if (share.state === "done"){
    html += '<div class="item-sub">已导入企业供应商：' + esc(share.account || "WorkBuddy 账号") +
      '。管理员勾选要下发的模型后，同事就能用。</div>';
  } else {
    html += '<div class="item-sub">可以点上面的按钮重新共享。</div>';
  }
  detail.innerHTML = html + '</div>' + local;
  wbBindLocal();
  var cancel = document.getElementById("wbCancel");
  if (cancel) cancel.addEventListener("click", wbCancel);
  var urlLink = document.getElementById("wbUrl");
  if (urlLink) urlLink.addEventListener("click", function(){
    var range = document.createRange();
    range.selectNodeContents(urlLink);
    var selection = window.getSelection();
    if (!selection) return;
    selection.removeAllRanges();
    selection.addRange(range);
  });
}

function wbPoll(){
  clearTimeout(wbPoll.timer);
  var share = state.share;
  if (!share || share.state !== "waiting" || !share.id) return;
  wbPoll.timer = setTimeout(function(){
    api("/v1/share/workbuddy/" + encodeURIComponent(share.id)).then(function(result){
      if (!result.ok){
        if (result.status === 404){ state.share = null; wbDraw(); return; }
        if (result.status === 401 || result.status === 403) return;
        wbPoll();
        return;
      }
      state.share = result.body.share || share;
      wbDraw();
      if (state.share.state === "waiting"){ wbPoll(); return; }
      if (state.share.state !== "done") return;
      toast("WorkBuddy 账号已导入企业供应商");
      api("/v1/sync", { method: "POST" }).then(function(synced){
        if (synced.ok && synced.body.status) drawUser(synced.body.status);
      });
    });
  }, 2000);
}

function wbStart(provider){
  // The frame magpie shows a plugin page in can't open a tab, so the local
  // service opens the vendor's page in this computer's browser and says
  // whether it could; the address below is what to copy when it couldn't.
  api("/v1/share/workbuddy/start", { method: "POST", body: { provider: provider } }).then(function(result){
    if (!result.ok){ toast(messageOf(result, "发起共享失败"), "error"); return; }
    state.share = result.body.share || null;
    wbDraw();
    var url = state.share && state.share.url;
    var said = result.body.instructions
      || (url && result.body.opened ? "已在浏览器打开 WorkBuddy 登录页，扫码后回到这里"
        : url ? "请复制下面的链接到浏览器打开，扫码后回到这里" : "");
    if (said) toast(said, url && !result.body.opened ? "error" : "");
    wbPoll();
  });
}

// wbImport moves one of this computer's own sign-ins to the corporate
// gateway. It asks first: the account leaves this magpie, and signing in
// again here is the way back.
function wbImport(index){
  var item = wbLocalItems()[index];
  if (!item) return;
  var label = text(item.account) || "WorkBuddy 账号";
  if (!window.confirm("把本机 magpie 的 " + label + " 登录导入企业网关？导入后本机 magpie 会退出这个 WorkBuddy 账号，可随时重新登录。")) return;
  state.importing = true;
  wbDraw();
  api("/v1/share/workbuddy/import", {
    method: "POST",
    body: { provider: item.provider, account: item.account }
  }).then(function(result){
    state.importing = false;
    if (!result.ok){ wbDraw(); toast(messageOf(result, "导入失败"), "error"); return; }
    state.share = (result.body && result.body.share) || state.share;
    toast(result.body && result.body.removed === false
      ? "已导入企业网关；本机登录未能退出，请在 magpie 里退出该账号"
      : "已导入企业网关，本机已退出该账号");
    api("/v1/status").then(function(refreshed){
      if (refreshed.ok && refreshed.body) drawUser(refreshed.body);
      else wbDraw();
      api("/v1/sync", { method: "POST" }).then(function(synced){
        if (synced.ok && synced.body.status) drawUser(synced.body.status);
      });
    });
  });
}

function wbCancel(){
  var share = state.share;
  if (!share) return;
  api("/v1/share/workbuddy/" + encodeURIComponent(share.id) + "/cancel", { method: "POST" }).then(function(result){
    if (!result.ok){ toast(messageOf(result, "取消失败"), "error"); return; }
    state.share = result.body.share || share;
    wbDraw();
  });
}

function wbLoad(){
  if (!(state.status && state.status.device && state.status.device.enrolled)){ wbDraw(); return; }
  api("/v1/share/workbuddy").then(function(result){
    if (result.ok){
      var shares = (result.body && result.body.shares) || [];
      var waiting = shares.filter(function(item){ return item.state === "waiting"; })[0];
      if (waiting) state.share = waiting;
      else if (shares.length) state.share = shares[0];
    }
    wbDraw();
    wbPoll();
  });
}

function drawGate(session){
  var user = (session && session.user) || {};
  var gate = document.getElementById("adminGate");
  gate.hidden = false;
  document.getElementById("adminBody").hidden = true;
  gate.innerHTML =
    '<h2>需要企业管理员身份</h2>' +
    '<p class="muted">当前登录：' + esc(user.email || "未登录") + '（' + esc(user.role || "member") + '）</p>' +
    '<p class="muted">' + esc((session && session.reason) || "登录后重试。") + '</p>' +
    '<div class="empty" style="text-align:left;margin-top:12px">服务端把下面这些账号视为管理员：' +
      '<br>· 登录令牌的 groups 含 <code>corp-admins</code>、<code>magpie-admins</code> 或 <code>admins</code>（可用 <code>CORP_ADMIN_GROUPS</code> 覆盖）' +
      '<br>· 邮箱在 <code>CORP_ADMIN_EMAILS</code> 里' +
      '<br>· 演示环境：登录页点「演示登录（管理员）」，或服务端设了 <code>CORP_DEMO_ADMIN=true</code>' +
    '</div>' +
    '<p style="margin-top:12px"><a class="btn" href="/login?renew=1">以管理员身份重新登录</a></p>';
}

function drawAdmin(session){
  state.session = session;
  if (!session || !session.admin){
    drawGate(session || {});
    return;
  }
  document.getElementById("adminGate").hidden = true;
  document.getElementById("adminBody").hidden = false;

  var sharing = session.sharing || {};
  var catalog = sharing.catalog || [];
  document.getElementById("sharingMode").innerHTML =
    '<div class="big">' + esc(modeLabel(sharing.mode)) + '</div>' +
    '<div class="row"><span>更新时间</span><strong>' + esc(when(sharing.updatedAt)) + '</strong></div>' +
    '<div class="row"><span>企业网关</span><strong>' + esc(text(session.gateway && session.gateway.baseUrl)) + '</strong></div>' +
    '<div class="row"><span>本机 magpie</span><strong>' + esc(text(session.gateway && session.gateway.local)) + '</strong></div>';
  document.getElementById("sharingCatalog").innerHTML = catalog.length
    ? '<div class="big">' + count(catalog.length) + ' <span class="muted" style="font-size:12px;font-weight:500">个模型</span></div><div class="chips">' + chips(catalog, 24) + '</div>'
    : '<div class="empty">还没有共享模型。选择原生供应商，或以 Remote magpie 分享。</div>';

  var sources = sharing.sources || [];
  document.getElementById("sharingSources").innerHTML = sources.length
    ? sources.map(function(source){
        return '<div class="item" data-mark="' + esc(markOf(source.name || source.id)) + '"><div class="item-main"><div class="item-title">' + esc(source.name) +
          (source.keyMasked ? ' <span class="chip">' + esc(source.keyMasked) + '</span>' : '') + '</div>' +
          '<div class="item-sub"><code>' + esc(source.id) + '</code> · ' + count(source.modelCount) + ' 个模型' +
          (source.keyCount ? ' · ' + count(source.keyCount) + ' 个 Key' : '') +
          (source.available === false ? ' · 不可用' : '') + '</div></div>' +
          '<div class="item-side">' + (source.available === false
            ? '<span class="pill warn">不可用</span>'
            : '<span class="pill ok">已分享</span>') + '</div></div>';
      }).join("")
    : '<div class="empty">当前没有共享来源。</div>';

  drawNative(session.native || { providers: [], keys: [] });
  drawNativeKeys((session.native && session.native.keys) || []);
  loadAdminWorkbuddy();
}

// drawAdminWorkbuddy is the tick: of what employees shared into the
// gateway, which models the corporation hands out. Nothing is ticked for
// the administrator, so a share never opens every model by itself.
function drawAdminWorkbuddy(payload){
  var host = document.getElementById("wbAdminList");
  if (!host) return;
  var sources = (payload && Array.isArray(payload.sources)) ? payload.sources : [];
  if (!sources.length){
    host.innerHTML = '<div class="empty">还没有员工共享 WorkBuddy 账号。员工在「概览」页扫码登录后，账号会出现在这里。</div>';
    return;
  }
  var serving = payload.serving !== false;
  host.innerHTML = sources.map(function(source){
    var selected = Array.isArray(source.selected) ? source.selected : [];
    var models = Array.isArray(source.models) ? source.models : [];
    var people = (Array.isArray(source.accounts) ? source.accounts : [])
      .map(function(item){ return text(item.account) || text(item.email); })
      .filter(Boolean);
    return '<div class="item" data-mark="' + esc(markOf(source.name || source.provider)) + '"><div class="item-main">' +
      '<div class="item-title">' + esc(source.name || source.provider) +
        ' <span class="pill">' + esc(source.provider) + '</span></div>' +
      (people.length ? '<div class="item-sub">共享人：' + esc(people.join("、")) + '</div>' : '') +
      (models.length
        ? '<div>' + models.map(function(model){
            return '<label class="check"><input type="checkbox" data-wb-provider="' + esc(source.provider) +
              '" data-wb-model="' + esc(model) + '"' + (selected.indexOf(model) >= 0 ? " checked" : "") +
              '> ' + esc(model) + '</label>';
          }).join("") + '</div>'
        : '<div class="item-sub">这个账号还没有列出模型。</div>') +
      (serving ? '' : '<div class="item-sub" style="color:var(--warn)">当前分享模式是关闭的：勾选会保存，开启分享后才下发。</div>') +
      '</div></div>';
  }).join("");
}

function loadAdminWorkbuddy(){
  if (!document.getElementById("wbAdminList")) return;
  api("/v1/admin/workbuddy").then(function(result){
    if (!result.ok) return;
    drawAdminWorkbuddy(result.body || {});
  });
}

function saveAdminWorkbuddy(button){
  var groups = {};
  var inputs = document.querySelectorAll("input[data-wb-model]");
  Array.prototype.forEach.call(inputs, function(input){
    var provider = input.getAttribute("data-wb-provider");
    if (!groups[provider]) groups[provider] = [];
    if (input.checked) groups[provider].push(input.getAttribute("data-wb-model"));
  });
  var providers = Object.keys(groups);
  if (!providers.length){ toast("还没有可下发的模型", "error"); return; }
  button.disabled = true;
  button.textContent = "下发中…";
  Promise.all(providers.map(function(provider){
    return api("/v1/admin/workbuddy", { method: "PUT", body: { provider: provider, models: groups[provider] } });
  })).then(function(results){
    button.disabled = false;
    button.textContent = "下发选中";
    var failed = results.filter(function(result){ return !result.ok; })[0];
    if (failed){ toast(messageOf(failed, "下发失败"), "error"); return; }
    toast("已下发；客户端下次同步会拿到这些模型");
    loadAdmin();
  });
}

function drawNative(native){
  var host = document.getElementById("nativeList");
  var providers = Array.isArray(native.providers) ? native.providers : [];
  if (!providers.length){
    host.innerHTML = '<div class="empty">没有读到本机 magpie 的供应商。确认这台机器上的 magpie 已经添加供应商，' +
      '并且插件能读到 <code>' + esc(native.configDir || "magpie 配置目录") + '</code>。</div>';
    return;
  }
  var known = {};
  providers.forEach(function(provider){
    known[provider.id] = true;
    if (!(provider.id in state.selected)) state.selected[provider.id] = false;
  });
  Object.keys(state.selected).forEach(function(id){
    if (!known[id]) delete state.selected[id];
  });
  host.innerHTML = providers.map(function(provider){
    var checked = state.selected[provider.id] ? " checked" : "";
    var disabled = provider.shareable ? "" : " disabled";
    return '<label class="item" data-mark="' + esc(markOf(provider.preset || provider.name || provider.id)) + '" style="cursor:' + (provider.shareable ? "pointer" : "default") + '">' +
      '<div class="item-main">' +
        '<div class="item-title"><input type="checkbox" data-native="' + esc(provider.id) + '"' + checked + disabled + '> ' +
          esc(provider.name) + ' <span class="pill">' + esc(provider.preset || "自定义") + '</span></div>' +
        '<div class="item-sub"><code>' + esc(provider.id) + '</code> · ' + count(provider.modelCount) + ' 个模型 · ' +
          count(provider.keyCount) + ' 个 Key' +
          (provider.maskedKeys && provider.maskedKeys.length ? '（' + esc(provider.maskedKeys.join("  ")) + '）' : '') + '</div>' +
        (provider.reason ? '<div class="item-sub" style="color:var(--warn)">' + esc(provider.reason) + '</div>' : '') +
        (provider.models && provider.models.length ? '<div class="chips">' + chips(provider.models, 6) + '</div>' : '') +
      '</div>' +
      '<div class="item-side"><span class="pill ' + (provider.shareable ? "ok" : "warn") + '">' +
        (provider.shareable ? "可分享" : "不可分享") + '</span></div></label>';
  }).join("");
  Array.prototype.forEach.call(host.querySelectorAll("input[data-native]"), function(input){
    input.addEventListener("change", function(){
      state.selected[input.getAttribute("data-native")] = input.checked;
    });
  });
}

function drawNativeKeys(keys){
  var host = document.getElementById("nativeKeys");
  if (!keys.length){
    host.innerHTML = '<div class="empty">本机 magpie 还没有网关密钥。</div>';
    return;
  }
  host.innerHTML = keys.map(function(key){
    var stateLabel = key.off ? "已停用" : key.readOnly ? "只读" : key.usable ? "可用" : "不可用";
    var tone = key.usable ? "ok" : "warn";
    return '<div class="item" data-mark="' + esc(markOf(key.name || "K")) + '"><div class="item-main">' +
      '<div class="item-title">' + esc(key.name) + ' <span class="pill ' + tone + '">' + stateLabel + '</span></div>' +
      '<div class="item-sub"><code>' + esc(key.masked || "…") + '</code>' +
        (key.models && key.models.length ? ' · ' + count(key.models.length) + ' 个模型' : ' · 全部模型') +
        (key.limit && key.limit.period ? ' · ' + esc(key.limit.period) + ' 限额' : '') + '</div></div></div>';
  }).join("");
}

function keyForm(deviceId, key){
  var limit = key.limit || {};
  var period = limit.period || "";
  var options = [["", "不限额"], ["day", "每天"], ["week", "每周"], ["month", "每月"], ["hours", "滚动小时"], ["days", "滚动天"]]
    .map(function(pair){
      return '<option value="' + pair[0] + '"' + (period === pair[0] ? " selected" : "") + '>' + pair[1] + '</option>';
    }).join("");
  return '<form class="edit" data-device="' + esc(deviceId) + '" data-days="' + esc(limit.days || "") + '" data-hours="' + esc(limit.hours || "") + '">' +
    '<label class="field edit-wide"><span>可用模型（逗号分隔，留空 = 全部）</span>' +
      '<input name="models" value="' + esc((key.models || []).join(", ")) + '" placeholder="deepseek-v4-pro, kimi-k3"></label>' +
    '<label class="field"><span>额度周期</span><select name="period">' + options + '</select></label>' +
    '<label class="field"><span>Token 额度</span><input name="tokens" inputmode="numeric" value="' + esc(limit.tokens || "") + '" placeholder="可选"></label>' +
    '<label class="field"><span>费用额度（USD）</span><input name="cost" inputmode="decimal" value="' + esc(limit.cost || "") + '" placeholder="可选"></label>' +
    '<div class="edit-wide" style="display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap">' +
      '<div><label class="check"><input type="checkbox" name="readOnly"' + (key.readOnly ? " checked" : "") + '> 只读</label>' +
      '<label class="check"><input type="checkbox" name="off"' + (key.state === "disabled" ? " checked" : "") + '> 停用这条 Key</label></div>' +
      '<button class="btn primary sm" type="submit">保存</button>' +
    '</div></form>';
}

function drawPeople(data){
  state.people = data;
  var host = document.getElementById("people");
  var people = (data && data.people) || [];
  document.getElementById("peopleCount").textContent = people.length + " 人";
  if (!people.length){
    host.innerHTML = '<div class="empty">还没有人领取密钥。员工在插件里登录后，这里会出现他们的设备与网关 Key。</div>';
    return;
  }
  host.innerHTML = people.map(function(person){
    var devices = person.devices || [];
    var rows = devices.map(function(device){
      var key = device.key;
      if (!key){
        return '<div class="device"><div class="device-head"><strong>' + esc(device.name || device.id) + '</strong>' +
          '<span class="pill warn">没有网关 Key</span></div>' +
          '<div class="item-sub">' + esc(device.state) + ' · ' + esc(when(device.createdAt)) + '</div></div>';
      }
      return '<div class="device">' +
        '<div class="device-head"><div><strong>' + esc(device.name || device.id) + '</strong> ' +
          '<span class="pill ' + (key.state === "enabled" ? "ok" : "warn") + '">' + esc(key.state) + '</span> ' +
          '<span class="chip">' + esc(key.masked || "") + '</span></div>' +
          '<span class="muted small">' + esc(device.platform || "") + ' · 到期 ' + esc(when(device.expiresAt)) + '</span></div>' +
        '<div class="item-sub">Key <code>' + esc(key.id) + '</code></div>' +
        keyForm(device.id, key) +
      '</div>';
    }).join("");
    return '<div class="person"><div class="person-head">' +
      '<div class="who"><div class="avatar">' + esc(String(person.email || "?").slice(0, 1).toUpperCase()) + '</div>' +
        '<div><div class="item-title">' + esc(person.name || person.email) +
          (person.role === "admin" ? ' <span class="pill accent">管理员</span>' : '') + '</div>' +
        '<div class="item-sub">' + esc(person.email) + ' · ' + esc((person.groups || []).join(" / ") || "无分组") + '</div></div></div>' +
      '<span class="pill">' + devices.length + ' 台设备</span></div>' +
      (rows || '<div class="empty" style="margin-top:10px">没有设备</div>') + '</div>';
  }).join("");
  bindKeyForms();
}

function bindKeyForms(){
  Array.prototype.forEach.call(document.querySelectorAll("form[data-device]"), function(form){
    form.addEventListener("submit", function(event){
      event.preventDefault();
      var button = form.querySelector("button[type=submit]");
      var models = String(form.elements.models.value || "").split(",")
        .map(function(model){ return model.trim(); }).filter(Boolean);
      var period = form.elements.period.value;
      var body = {
        models: models,
        readOnly: form.elements.readOnly.checked,
        off: form.elements.off.checked
      };
      if (period){
        var tokens = Number(form.elements.tokens.value || 0);
        var cost = Number(form.elements.cost.value || 0);
        var limit = { period: period };
        if (period === "days") limit.days = Number(form.getAttribute("data-days") || 0) || 30;
        if (period === "hours") limit.hours = Number(form.getAttribute("data-hours") || 0) || 24;
        if (tokens > 0) limit.tokens = Math.trunc(tokens);
        if (cost > 0) limit.cost = cost;
        if (!limit.tokens && !limit.cost){
          toast("选了额度周期，就填 Token 或费用额度", "error");
          return;
        }
        body.limit = limit;
      } else {
        body.limit = null;
      }
      button.disabled = true;
      button.textContent = "保存中…";
      api("/v1/admin/people/" + encodeURIComponent(form.getAttribute("data-device")), { method: "PATCH", body: body })
        .then(function(result){
          button.disabled = false;
          button.textContent = "保存";
          if (!result.ok){ toast(messageOf(result, "保存失败"), "error"); return; }
          toast("已更新 " + (result.body.key && result.body.key.name ? result.body.key.name : "网关 Key"));
          loadPeople();
        });
    });
  });
}

function loadPeople(){
  return api("/v1/admin/people").then(function(result){
    if (!result.ok){ toast(messageOf(result, "读取人员失败"), "error"); return; }
    drawPeople(result.body);
    if (result.body.gateway && result.body.gateway.error){
      banner("网关密钥读取失败：" + result.body.gateway.error, "warn");
    }
  });
}

function loadAdmin(){
  banner("");
  return api("/v1/admin/session").then(function(result){
    if (!result.ok){
      drawGate({ user: INITIAL.device, reason: messageOf(result, "读取管理员状态失败") });
      return;
    }
    drawAdmin(result.body);
    if (result.body.admin) loadPeople();
  });
}

// ---- the sign-in page -------------------------------------------------
//
// The browser tab the identity provider returns to cannot call this
// service, so this page asks the service to start the sign-in and then
// polls until a usable device lands. Nothing here holds the device token.

function waitForSignIn(attempt){
  api("/v1/status").then(function(result){
    if (result.ok && result.body.device && result.body.device.enrolled && result.body.device.usable){
      location.replace("/");
      return;
    }
    if (attempt >= 90) return;
    setTimeout(function(){ waitForSignIn(attempt + 1); }, 2000);
  });
}

function loginBoot(){
  var button = document.getElementById("login");
  var hint = document.getElementById("authHint");
  // The first render cannot know whether the server offers demo sign-in:
  // that comes from its discovery answer. Ask once, and reveal the demo
  // box and the address field only for what this server actually is.
  api("/v1/status").then(function(result){
    if (!result.ok || !result.body) return;
    var demo = document.getElementById("demoBox");
    if (demo) demo.className = result.body.configured && result.body.demoSignIn ? "demo on" : "demo";
    var config = document.getElementById("authConfig");
    if (config) config.hidden = Boolean(result.body.configured);
    if (button && result.body.configured) button.disabled = false;
  });
  on("cfg-save", "click", function(event){
    var input = document.getElementById("cfg-url");
    var target = event.target;
    target.disabled = true;
    api("/v1/config", { method: "POST", body: { baseUrl: input ? input.value.trim() : "" } }).then(function(result){
      target.disabled = false;
      if (!result.ok){ toast(messageOf(result, "保存地址失败"), "error"); return; }
      document.getElementById("authConfig").hidden = true;
      if (button) button.disabled = false;
      toast("地址已保存");
    });
  });
  if (button) button.addEventListener("click", function(){
    button.disabled = true;
    button.textContent = "等待浏览器登录…";
    api("/v1/login", { method: "POST" }).then(function(result){
      if (!result.ok){
        button.disabled = false;
        button.textContent = "使用企业账号登录";
        toast(messageOf(result, "登录失败"), "error");
        return;
      }
      if (hint) hint.textContent = "已在浏览器中打开登录页；完成后这个页面会自动继续。";
      waitForSignIn(0);
    });
  });
  function demoSignIn(role){
    return function(event){
      var input = document.getElementById("demo-email");
      var target = event.target;
      target.disabled = true;
      api("/v1/demo-login", { method: "POST", body: { email: input ? input.value : "", role: role } }).then(function(result){
        target.disabled = false;
        if (!result.ok){ toast(messageOf(result, "演示登录失败"), "error"); return; }
        location.replace("/");
      });
    };
  }
  on("demo-login", "click", demoSignIn("member"));
  on("demo-admin", "click", demoSignIn("admin"));
}

// ---- the personal page ------------------------------------------------

function drawMe(s){
  state.status = s;
  var device = s.device || {};
  var role = s.role || device.role || "member";
  var name = device.name || device.email || "企业成员";
  document.getElementById("meAvatar").textContent = String(name).slice(0, 1).toUpperCase() || "?";
  document.getElementById("meName").textContent = name;
  document.getElementById("meEmail").textContent = device.email || "—";
  document.getElementById("mePills").innerHTML =
    '<span class="pill ' + (device.enrolled && device.usable ? "ok" : "warn") + '"><span class="dot"></span>' +
      (device.enrolled ? (device.usable ? "登录有效" : "登录已过期") : "未登录") + '</span>' +
    (role === "admin" ? '<span class="pill accent">管理员</span>' : "") +
    (device.department ? '<span class="pill">' + esc(device.department) + '</span>' : "");

  var groups = Array.isArray(device.groups) ? device.groups : [];
  document.getElementById("meFacts").innerHTML =
    '<div class="row"><span>姓名</span><strong>' + esc(text(device.name)) + '</strong></div>' +
    '<div class="row"><span>邮箱</span><strong>' + esc(text(device.email)) + '</strong></div>' +
    '<div class="row"><span>部门</span><strong>' + esc(text(device.department)) + '</strong></div>' +
    '<div class="row"><span>角色</span><strong>' + (role === "admin" ? "管理员" : "成员") + '</strong></div>' +
    '<div class="row"><span>分组</span><strong>' + esc(groups.join(" / ") || "无分组") + '</strong></div>';

  document.getElementById("meDevice").innerHTML =
    '<div class="row"><span>设备 ID</span><strong><code>' + esc(text(device.deviceId)) + '</code></strong></div>' +
    '<div class="row"><span>登录时间</span><strong>' + esc(when(device.enrolledAt)) + '</strong></div>' +
    '<div class="row"><span>状态</span><strong>' + (device.usable ? "可用" : "不可用") + '</strong></div>';

  document.getElementById("meCredential").innerHTML =
    '<div class="row"><span>到期</span><strong>' + esc(when(device.expiresAt)) + '</strong></div>' +
    '<div class="row"><span>续期时间</span><strong>' + esc(when(device.refreshAfter)) + '</strong></div>' +
    '<div class="empty" style="margin-top:10px">凭据只保存在本机插件里，页面不接触它。</div>';

  var models = (s.providers || []).reduce(function(total, provider){ return total + Number(provider.models || 0); }, 0);
  document.getElementById("meGateway").innerHTML =
    '<div class="row"><span>地址</span><strong>' + esc(text(device.gateway || s.baseUrl)) + '</strong></div>' +
    '<div class="row"><span>供应商</span><strong>' + count((s.providers || []).length) + '</strong></div>' +
    '<div class="row"><span>模型</span><strong>' + count(models) + '</strong></div>' +
    '<div class="row"><span>分享模式</span><strong>' + esc(modeLabel(s.sharing && s.sharing.mode)) + '</strong></div>';

  document.getElementById("meSync").innerHTML =
    '<div class="row"><span>上次同步</span><strong>' + esc(s.lastSyncAt ? when(s.lastSyncAt) : "从未同步") + '</strong></div>' +
    '<div class="row"><span>资源版本</span><strong>' + esc(s.revision || "—") + '</strong></div>' +
    '<div class="row"><span>上次上传</span><strong>' + esc(lastUpload(s.lastUploadAt)) + '</strong></div>' +
    '<div class="row"><span>上传</span><strong>' + (s.upload && (s.upload.usage || s.upload.masking || s.upload.sessions) ? "已开启" : "关闭") + '</strong></div>' +
    '<div class="row"><span>上次错误</span><strong>' + esc(s.lastSyncError || "无") + '</strong></div>';

  document.getElementById("meResources").innerHTML = resourceColumns(s.resources);
}

function drawMeShares(shares){
  var card = document.getElementById("meWorkbuddy");
  if (!card) return;
  var list = Array.isArray(shares) ? shares : [];
  card.hidden = !list.length;
  if (!list.length) return;
  document.getElementById("meShares").innerHTML = list.map(function(share){
    return '<div class="item" data-mark="' + esc(markOf(share.providerName || share.provider)) + '"><div class="item-main">' +
      '<div class="item-title">' + esc(share.providerName || share.provider) + '</div>' +
      '<div class="item-sub">' + esc(text(share.account)) + ' · ' + count((share.models || []).length) + ' 个模型 · ' +
        esc(when(share.updatedAt || share.createdAt)) + '</div></div>' +
      '<div class="item-side"><span class="pill ' +
        (share.state === "done" ? "ok" : share.state === "failed" ? "err" : "warn") + '">' +
        esc(wbStateLabel(share.state)) + '</span></div></div>';
  }).join("");
}

function loadMeShares(){
  if (!document.getElementById("meWorkbuddy")) return;
  api("/v1/share/workbuddy").then(function(result){
    if (result.ok) drawMeShares((result.body && result.body.shares) || []);
  });
}

// ---- what each page binds ---------------------------------------------

if (PAGE === "login"){
  loginBoot();
}

if (PAGE === "overview"){
  drawUser(INITIAL);
  wbLoad();
}

if (PAGE === "me"){
  drawMe(INITIAL);
  loadMeShares();
}

if (PAGE === "admin"){
  loadAdmin();
  on("nativeShare", "click", function(event){
    var button = event.target;
    var ids = Object.keys(state.selected).filter(function(id){ return state.selected[id]; });
    if (!ids.length){ toast("先勾选要分享的供应商", "error"); return; }
    button.disabled = true;
    button.textContent = "分享中…";
    api("/v1/admin/share/native", { method: "POST", body: { ids: ids } }).then(function(result){
      button.disabled = false;
      button.textContent = "分享选中";
      if (!result.ok){ toast(messageOf(result, "分享失败"), "error"); return; }
      var skipped = (result.body.skipped || []).length;
      toast(skipped ? ("已分享，跳过 " + skipped + " 个不可分享项") : "已分享到企业网关");
      loadAdmin();
    });
  });
  on("remoteShare", "click", function(event){
    var button = event.target;
    var models = document.getElementById("remoteModels").value.split(",")
      .map(function(model){ return model.trim(); }).filter(Boolean);
    button.disabled = true;
    button.textContent = "分享中…";
    api("/v1/admin/share/remote", { method: "POST", body: { models: models } }).then(function(result){
      button.disabled = false;
      button.textContent = "以 Remote magpie 分享";
      if (!result.ok){ toast(messageOf(result, "分享失败"), "error"); return; }
      toast("已按 Remote magpie 分享企业网关");
      loadAdmin();
    });
  });
  on("shareOff", "click", function(event){
    var button = event.target;
    button.disabled = true;
    api("/v1/admin/share/off", { method: "POST" }).then(function(result){
      button.disabled = false;
      if (!result.ok){ toast(messageOf(result, "停止分享失败"), "error"); return; }
      toast("已停止分享企业供应商");
      loadAdmin();
    });
  });
  on("adminRefresh", "click", function(){ loadAdmin(); toast("已刷新"); });
  on("peopleRefresh", "click", function(){ loadPeople(); });
  on("wbAdminSave", "click", function(event){ saveAdminWorkbuddy(event.target); });
}

on("sync", "click", function(event){
  var button = event.target;
  var label = button.textContent;
  button.disabled = true;
  button.textContent = "同步中…";
  api("/v1/sync", { method: "POST" }).then(function(result){
    button.disabled = false;
    button.textContent = label;
    if (!result.ok){ toast(messageOf(result, "同步失败"), "error"); return; }
    if (PAGE === "me") drawMe(result.body.status); else drawUser(result.body.status);
    var errors = (result.body.summary && result.body.summary.errors) || [];
    toast(errors.length ? (errors[0].message || "同步有错误") : "同步完成", errors.length ? "error" : "");
  });
});

if (PAGE !== "login"){
  setInterval(function(){
    api("/v1/status").then(function(result){
      if (!result.ok || !result.body.device) return;
      if (PAGE === "me") drawMe(result.body);
      else if (PAGE === "overview") drawUser(result.body);
    });
  }, 15000);
}
`;

function escapeJson(value) {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

function pageHeader(active) {
  const tab = (href, label) =>
    `<a class="tab${active === href ? " is-on" : ""}" href="${href}"${active === href ? ' aria-current="page"' : ""}>${label}</a>`;
  return [
    '<header class="top">',
    '  <div class="brand"><div class="logo">企</div><div>',
    "    <h1>企业网关</h1>",
    '    <p class="sub">本机从企业拿到的供应商与资源；管理员可以在这里决定分享什么。</p>',
    "  </div></div>",
    '  <nav class="tabs" aria-label="页面">',
    tab("/", "概览"),
    tab("/me", "个人信息"),
    tab("/admin", "管理员"),
    "  </nav>",
    "</header>",
    '<p id="banner" class="banner" role="status" hidden></p>',
  ].join("\n");
}

// The sign-in page stands alone: it has no navigation, and it is the only
// page a computer without a device may load.
function loginPage(status) {
  const corporate = status.corporate ? ` ${escapeHtml(status.corporate)}` : "企业网关";
  return [
    '<main class="auth">',
    '  <section class="card">',
    '    <div class="logo">企</div>',
    `    <h1>登录${corporate}</h1>`,
    '    <p class="muted small">用企业账号登录一次，本机 magpie 会从企业网关领取一把密钥，并同步供应商、指令、MCP 与技能。密钥只保存在本机插件里，不会出现在页面上。</p>',
    `    <div id="authConfig"${status.configured ? " hidden" : ""}>`,
    '      <label class="field"><span>企业服务端地址</span>',
    `        <input id="cfg-url" type="url" inputmode="url" placeholder="https://control.corp.example" value="${escapeHtml(status.baseUrl || "")}"></label>`,
    '      <button id="cfg-save" class="btn" type="button">保存地址</button>',
    "    </div>",
    `    <button id="login" class="btn primary" type="button"${status.configured ? "" : " disabled"}>使用企业账号登录</button>`,
    '    <p class="muted small" id="authHint">登录会在系统浏览器中打开飞书 / 企业 SSO，完成后这个页面会自动继续。</p>',
    `    <div id="demoBox" class="demo${status.configured && status.demoSignIn ? " on" : ""}">`,
    '      <input id="demo-email" type="email" placeholder="alice@corp.example" value="alice@corp.example">',
    '      <button id="demo-login" class="btn" type="button">演示登录</button>',
    '      <button id="demo-admin" class="btn" type="button">演示登录（管理员）</button>',
    '      <p class="muted small" style="flex:1 1 100%;margin:0">演示账号只在本机演示服务上可用；管理员入口会直接拿到管理员视图。</p>',
    "    </div>",
    "  </section>",
    '  <p class="auth-note muted small">登录后可在「个人信息」查看本机设备、凭据和已同步的供应商。</p>',
    "</main>",
  ].join("\n");
}

function personalPage() {
  return [
    '<main id="profileView">',
    '  <article class="card">',
    '    <div class="profile-head">',
    '      <div class="who"><div class="avatar lg" id="meAvatar">?</div>',
    '        <div><h2 id="meName">—</h2><div class="item-sub" id="meEmail">—</div></div></div>',
    '      <div class="chips" id="mePills"></div>',
    "    </div>",
    '    <div class="facts" id="meFacts"></div>',
    "  </article>",
    '  <div class="grid">',
    '    <article class="card"><h2>设备</h2><div id="meDevice"></div></article>',
    '    <article class="card"><h2>凭据</h2><div id="meCredential"></div></article>',
    "  </div>",
    '  <div class="grid">',
    '    <article class="card"><h2>企业网关</h2><div id="meGateway"></div></article>',
    '    <article class="card"><h2>同步与上传</h2><div id="meSync"></div></article>',
    "  </div>",
    '  <article class="card"><div class="card-head"><h2>企业资源</h2></div><div id="meResources" class="resources"></div></article>',
    '  <article class="card" id="meWorkbuddy" hidden><div class="card-head"><h2>共享的 WorkBuddy 账号</h2></div><div id="meShares" class="list"></div></article>',
    '  <div class="actions">',
    '    <button id="sync" class="btn primary" type="button">立即同步</button>',
    '    <a class="btn" href="/login?renew=1">重新登录</a>',
    '    <a class="btn" href="/">返回概览</a>',
    "  </div>",
    "</main>",
  ].join("\n");
}

function overviewPage() {
  return [
    '<main id="userView">',
    '  <div class="cards">',
    '    <article class="card"><div class="card-head"><h2>账号</h2><a class="link" href="/me">个人信息</a></div><div id="userAccount"></div></article>',
    '    <article class="card"><h2>企业网关</h2><div id="userGateway"></div></article>',
    '    <article class="card"><h2>同步</h2><div id="userSync"></div></article>',
    "  </div>",
    '  <div class="grid">',
    '    <article class="card"><div class="card-head"><h2>供应商</h2></div><div id="userProviders" class="list"></div></article>',
    '    <article class="card"><div class="card-head"><h2>分享来源</h2></div><div id="userSources" class="list"></div></article>',
    "  </div>",
    '  <article class="card" id="userWorkbuddy">',
    '    <div class="card-head"><h2>共享 WorkBuddy</h2></div>',
    '    <p class="muted small">扫码登录你自己的 WorkBuddy 账号，把它的模型导入企业网关。登录页由本机浏览器打开，打不开时可复制页面给出的地址；这里只保留账号和模型，不保存登录凭证。</p>',
    '    <div class="actions" id="wbButtons"></div>',
    '    <div id="wbDetail" class="list"></div>',
    "  </article>",
    '  <article id="userPluginsCard" class="card" hidden><div class="card-head"><h2>推荐安装的插件</h2></div><div id="userPlugins" class="list"></div></article>',
    '  <article class="card"><div class="card-head"><h2>企业资源</h2></div><div id="userResources" class="resources"></div></article>',
    '  <div class="actions">',
    '    <button id="sync" class="btn primary" type="button">立即同步</button>',
    '    <a class="btn" href="/login?renew=1">重新登录</a>',
    '    <a class="btn" href="/me">个人信息</a>',
    "  </div>",
    "</main>",
  ].join("\n");
}

function adminPage() {
  return [
    '<main id="adminView">',
    '  <div id="adminGate" class="card gate" hidden></div>',
    '  <div id="adminBody" hidden>',
    '    <div class="cards">',
    '      <article class="card"><h2>当前分享模式</h2><div id="sharingMode"></div></article>',
    '      <article class="card"><h2>共享模型</h2><div id="sharingCatalog"></div></article>',
    '      <article class="card"><h2>分享来源</h2><div id="sharingSources" class="list"></div></article>',
    "    </div>",
    '    <div class="grid">',
    '      <article class="card">',
    '        <div class="card-head"><h2>本机 magpie 供应商</h2><button id="nativeShare" class="btn primary sm" type="button">分享选中</button></div>',
    '        <p class="muted small">读取本机 magpie 的 providers.json。Key 只在本机服务与企业网关之间传递，不会出现在这个页面。</p>',
    '        <div id="nativeList" class="list"></div>',
    "      </article>",
    '      <article class="card">',
    "        <h2>以 Remote magpie 分享</h2>",
    '        <p class="muted small">企业网关本身就是一台 magpie 时，直接发布它的模型列表；客户端用网关 Key 访问。</p>',
    '        <label class="field"><span>模型（逗号分隔，留空则读取网关）</span>',
    '          <input id="remoteModels" placeholder="deepseek-v4-pro, kimi-k3"></label>',
    '        <div class="actions">',
    '          <button id="remoteShare" class="btn primary" type="button">以 Remote magpie 分享</button>',
    '          <button id="shareOff" class="btn danger" type="button">停止分享</button>',
    "        </div>",
    "      </article>",
    "    </div>",
    '    <article class="card">',
    '      <div class="card-head"><h2>员工共享的 WorkBuddy</h2><button id="wbAdminSave" class="btn primary sm" type="button">下发选中</button></div>',
    '      <p class="muted small">员工扫码后账号落在企业网关。这里勾选要下发给全公司的模型；没勾选的不进企业目录，分享模式为 off 时只保存、不下发。</p>',
    '      <div id="wbAdminList" class="list"></div>',
    "    </article>",
    '    <article class="card">',
    '      <div class="card-head"><h2>领取密钥的人员</h2><span id="peopleCount" class="pill"></span>',
    '        <button id="peopleRefresh" class="link" type="button">刷新</button></div>',
    '      <p class="muted small">每个人 enroll 时在网关建一条 caller key。这里设置它的模型白名单、只读、额度与启停。</p>',
    '      <div id="people" class="list"></div>',
    "    </article>",
    '    <article class="card">',
    '      <div class="card-head"><h2>本机 magpie 网关密钥</h2><button id="adminRefresh" class="link" type="button">刷新</button></div>',
    '      <p class="muted small">只读预览，便于核对本机 magpie 正在使用的 Key 与权限。</p>',
    '      <div id="nativeKeys" class="list"></div>',
    "    </article>",
    "  </div>",
    "</main>",
  ].join("\n");
}

export function renderPage({ token, status, page = "overview", theme = "" }) {
  const boot = `window.__CORP_TOKEN=${JSON.stringify(token)};window.__CORP_STATUS=${escapeJson(status)};window.__CORP_PAGE=${JSON.stringify(page)};`;
  const login = page === "login";
  const picked = theme === "dark" || theme === "light" ? theme : "";
  const main = login
    ? loginPage(status)
    : page === "me"
      ? personalPage()
      : page === "admin"
        ? adminPage()
        : overviewPage();
  return [
    "<!doctype html>",
    '<html lang="zh-CN"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    `<title>${login ? "登录 · " : ""}企业网关</title>`,
    // magpie's theme, carried in the URL and kept for the next page: the
    // window can choose Light or Dark itself, where the system may differ
    `<script>(function(){try{var p=new URLSearchParams(location.search).get("theme");if(p==="dark"||p==="light")localStorage.setItem("corp-theme",p);var t=${JSON.stringify(picked)}||localStorage.getItem("corp-theme");if(t==="dark"||t==="light")document.documentElement.dataset.theme=t}catch(e){}})()</script>`,
    `<style>${STYLE}</style></head><body${login ? ' class="auth-body"' : ""}>`,
    '<div class="wrap">',
    login ? "" : pageHeader(page === "me" ? "/me" : page === "admin" ? "/admin" : "/"),
    main,
    "</div>",
    '<div id="toast" class="toast" role="status" aria-live="polite" hidden></div>',
    `<script>${boot}</script>`,
    `<script>${SCRIPT}</script>`,
    "</body></html>",
  ].filter(Boolean).join("\n");
}
