(async () => {
  await magpie.ready;
  const lang = magpie.theme?.lang || "en";
  const TXT = {
    en: { title: "Enterprise providers", empty: "The enterprise has not distributed any providers yet.", unavailable: "Enterprise providers are unavailable.", badge: "Enterprise", live: "live", off: "off", missing: "missing", modelCount: "{n} models", keySet: "key set", keyMissing: "no key" },
    zh: { title: "企业下发供应商", empty: "企业尚未下发供应商。", unavailable: "企业供应商暂不可用。", badge: "企业", live: "可用", off: "已停用", missing: "缺失", modelCount: "{n} 个模型", keySet: "Key 已设置", keyMissing: "无 Key" },
    "zh-TW": { title: "企業下發供應商", empty: "企業尚未下發供應商。", unavailable: "企業供應商暫時無法使用。", badge: "企業", live: "可用", off: "已停用", missing: "缺失", modelCount: "{n} 個模型", keySet: "Key 已設定", keyMissing: "無 Key" },
    ja: { title: "エンタープライズプロバイダー", empty: "エンタープライズプロバイダーはまだありません。", unavailable: "エンタープライズプロバイダーは利用できません。", badge: "企業", live: "利用可能", off: "停止中", missing: "不足", modelCount: "{n} モデル", keySet: "キー設定済み", keyMissing: "キーなし" },
    de: { title: "Unternehmensanbieter", empty: "Das Unternehmen hat noch keine Anbieter verteilt.", unavailable: "Unternehmensanbieter sind nicht verfügbar.", badge: "Unternehmen", live: "aktiv", off: "aus", missing: "fehlt", modelCount: "{n} Modelle", keySet: "Schlüssel gesetzt", keyMissing: "kein Schlüssel" },
  };
  const dict = TXT[lang] || TXT.en;
  const t = (k, vars={}) => (dict[k] || TXT.en[k] || k).replace(/\{(\w+)\}/g, (_,n)=>String(vars[n]??""));
  const list = document.getElementById("list");
  const empty = document.getElementById("empty");
  const note = document.getElementById("note");
  function el(tag, cls, text){ const n=document.createElement(tag); if(cls) n.className=cls; if(text!==undefined) n.textContent=text; return n; }
  function row(p){
    const li = el("li","ep-item");
    const main = el("div","ep-main");
    main.append(el("span","ep-name", p.name || p.id), el("code","ep-id", p.id));
    const key = p.keyState==="set" ? t("keySet") : p.keyState==="subscription" ? t("keySet") : t("keyMissing");
    const state = p.off ? t("off") : p.ready ? t("live") : t("missing");
    const meta = el("span","ep-meta", [p.host, t("modelCount",{n:p.modelCount||(p.models||[]).length||0}), key, state].filter(Boolean).join(" · "));
    main.append(meta);
    const badge = el("span","ep-badge", t("badge"));
    li.append(main,badge);
    return li;
  }
  try {
    const data = await magpie.read("enterprise:providers");
    const rows = Array.isArray(data?.providers) ? data.providers : [];
    list.replaceChildren(...rows.map(row));
    empty.hidden = rows.length>0;
    empty.textContent = t("empty");
    note.hidden = true;
  } catch {
    list.replaceChildren();
    empty.hidden = true;
    note.hidden = false;
    note.textContent = t("unavailable");
  }
})();
