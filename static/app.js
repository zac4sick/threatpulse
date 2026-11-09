"use strict";
// ThreatPulse front end. Feed data is untrusted: the DOM is built with textContent only
// (never innerHTML), and only https/http links are rendered.
(() => {
  const SVG = "http://www.w3.org/2000/svg";
  const $ = id => document.getElementById(id);
  const el = (tag, attrs = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") n.className = v; else n.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids.flat()) if (k !== null && k !== undefined && k !== "") n.append(k instanceof Node ? k : String(k));
    return n;
  };
  const svg = (tag, attrs = {}, ...kids) => {
    const n = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    for (const k of kids) n.append(k instanceof Node ? k : document.createTextNode(String(k)));
    return n;
  };
  const safeUrl = u => (typeof u === "string" && /^https?:\/\//i.test(u)) ? u : null;
  const link = (u, text) => el("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, text);
  const host = u => { try { return new URL(u).hostname; } catch { return u; } };
  const fmt = n => n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? Math.round(n / 1e3) + "K" : String(n);
  const ago = iso => {
    const m = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 60000));
    return m < 60 ? `${m} min ago` : m < 1440 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} d ago`;
  };
  // Defang indicators so nobody clicks a live malware URL: hxxp://evil[.]com
  const defang = s => String(s).replace(/^http/i, "hxxp").replace(/\./g, "[.]");
  const store = {
    get: k => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  };

  let DATA = null;
  let region = store.get("tp-region") === "sa" ? "sa" : "global";
  const watchList = () => $("watch").value.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  const isWatched = v => watchList().some(w => `${v.vendor} ${v.product}`.toLowerCase().includes(w));
  const w = v => (v.watch || isWatched(v)) ? 1 : 0;

  // ------------------------------------------------------------------ vulnerabilities
  function card(v) {
    const ai = v.ai || {};
    const watched = v.watch || isWatched(v);
    const badges = [el("span", { class: "b " + v.priority }, v.priority)];
    if (watched) badges.push(el("span", { class: "b star", title: "On your stack" }, "★ My stack"));
    if (v.kev) badges.push(el("span", { class: "b hot" }, "Exploited"));
    if (v.ransomware) badges.push(el("span", { class: "b hot" }, "Ransomware"));
    if (v.epss) badges.push(el("span", { class: "b", title: "Chance of exploitation in the next 30 days" }, `EPSS ${Math.round(v.epss * 100)}%`));
    if (v.cvss) badges.push(el("span", { class: "b" }, `CVSS ${v.cvss}`));
    if (v.due) badges.push(el("span", { class: "b", title: "CISA remediation deadline" }, `Due ${v.due}`));
    badges.push(el("span", { class: "id" }, v.id));

    const more = el("details", {}, el("summary", {}, "Details & sources"));
    if (ai.who) more.append(el("p", {}, el("b", {}, "Who's at risk: "), ai.who));
    if (ai.prevent && ai.prevent.length) more.append(el("p", {}, el("b", {}, "Prevent")), el("ul", {}, ai.prevent.map(s => el("li", {}, s))));
    if (ai.what && v.summary) more.append(el("p", { class: "fix" }, v.summary));
    if (v.fix_full) more.append(el("p", { class: "fix" }, el("b", {}, "CISA action: "), v.fix_full));
    const links = (v.links || []).map(safeUrl).filter(Boolean);
    const news = (v.news || []).filter(n => safeUrl(n.link));
    more.append(el("ul", {},
      links.map(u => el("li", {}, link(u, host(u)))),
      news.map(n => el("li", {}, link(n.link, `${n.source}: ${n.title}`)))));

    return el("article", { class: "card " + v.priority },
      el("div", { class: "row" }, badges),
      el("h3", {}, v.title),
      el("p", {}, ai.what || v.summary),
      el("p", { class: "fix" }, el("b", {}, "Fix: "), v.fix),
      more);
  }

  function renderVulns() {
    const q = $("q").value.trim().toLowerCase(), pf = $("pf").value;
    const rows = DATA.vulns
      .filter(v => (!pf || (pf === "watch" ? isWatched(v) || v.watch : v.priority === pf)) &&
        (!q || `${v.id} ${v.title} ${v.vendor} ${v.product}`.toLowerCase().includes(q)))
      .sort((a, b) => w(b) - w(a));  // your stack floats up; stable sort keeps priority order
    $("list").replaceChildren(...(rows.length ? rows.map(card)
      : [el("div", { class: "empty" }, pf === "watch" ? "Nothing on your stack right now. Good news." : "Nothing matches.")]));
  }

  // ------------------------------------------------------------------ ransomware
  const victims = () => DATA.ransomware.filter(v => region === "global" || v.south_asia);

  function renderRansom() {
    const list = victims();
    const s = $("ransom");
    if (!list.length) {
      s.replaceChildren(el("div", { class: "empty" }, region === "sa"
        ? "No South Asian victims in the latest leak-site posts."
        : "Leak-site feed fills in on the next refresh."));
      return;
    }
    s.replaceChildren(
      el("p", { class: "note" }, "Alleged victims posted on ransomware leak sites"),
      ...list.slice(0, 100).map(r => el("div", { class: "v" },
        el("div", {}, el("b", {}, r.victim), el("br"),
          el("small", {}, [r.sector, r.country, r.domain].filter(Boolean).join(" · "))),
        el("div", { class: "r" }, el("b", {}, r.group), el("br"),
          el("small", {}, r.date),
          r.sources.length > 1 ? el("span", { class: "b two", title: r.sources.join(" + ") }, " 2 trackers") : null))));
  }

  // ------------------------------------------------------------------ breaches & IOCs
  function renderIntel() {
    const s = $("intel");
    const kids = [el("h2", {}, "Newly loaded data breaches")];
    if (DATA.breaches.length) {
      kids.push(...DATA.breaches.slice(0, 10).map(b => el("div", { class: "v" },
        el("div", {}, safeUrl(b.link) ? link(b.link, b.title) : el("b", {}, b.title), el("br"),
          el("small", {}, b.data.join(", "))),
        el("div", { class: "r" }, el("b", {}, fmt(b.count) + " accounts"), el("br"),
          el("small", {}, `breached ${b.breach_date}`)))));
    } else kids.push(el("div", { class: "empty" }, "Breach feed fills in on the next refresh."));

    kids.push(el("h2", {}, "Fresh malicious indicators (last 24 h, high confidence)"),
      el("p", { class: "note" }, "Defanged — block these, don't visit them"));
    if (DATA.iocs.length) {
      kids.push(...DATA.iocs.slice(0, 25).map(i => el("div", { class: "v" },
        el("div", {}, el("div", { class: "mono" }, defang(i.ioc)), el("small", {}, `${i.type} · ${i.threat}`)),
        el("div", { class: "r" }, el("b", {}, i.malware), el("br"), el("small", {}, `${i.confidence}% conf.`)))));
    } else kids.push(el("div", { class: "empty" }, "Add a free abuse.ch Auth-Key to switch on live IOCs."));

    const news = DATA.news.filter(n => safeUrl(n.link) && (region === "global" || n.south_asia));
    kids.push(el("h2", {}, region === "sa" ? "South Asia headlines" : "Headlines"));
    kids.push(news.length ? el("ul", {}, news.slice(0, 15).map(n => el("li", {}, link(n.link, n.title), " ", el("small", {}, `· ${n.source}`))))
      : el("div", { class: "empty" }, "No matching headlines right now."));
    s.replaceChildren(...kids);
  }

  // ------------------------------------------------------------------ trends
  function columnChart(obj, label) {
    const keys = Object.keys(obj); if (!keys.length) return el("div", { class: "empty" }, "Not enough data yet.");
    const W = 720, H = 170, pad = 22, max = Math.max(...Object.values(obj)), bw = (W - 8 * (keys.length - 1)) / keys.length;
    const g = svg("svg", { viewBox: `0 0 ${W} ${H + 18}`, class: "chart", role: "img", "aria-label": label });
    keys.forEach((k, i) => {
      const h = Math.max(2, (obj[k] / max) * (H - pad)), x = i * (bw + 8), y = H - h;
      g.append(svg("rect", { class: "bar", x, y, width: bw, height: h, rx: 3 }),
        svg("text", { x: x + bw / 2, y: y - 6, "text-anchor": "middle" }, obj[k]),
        svg("text", { x: x + bw / 2, y: H + 14, "text-anchor": "middle" }, k.split("-")[1] || k));
    });
    return g;
  }
  function barList(obj) {
    const e = Object.entries(obj); if (!e.length) return el("div", { class: "empty" }, "Not enough data yet.");
    const max = Math.max(...e.map(x => x[1]));
    return el("div", {}, e.map(([k, v]) => {
      const s = svg("svg", { viewBox: "0 0 100 10", preserveAspectRatio: "none", "aria-hidden": "true" },
        svg("rect", { x: 0, y: 0, height: 10, rx: 2, width: Math.max(2, (v / max) * 100) }));
      return el("div", { class: "hbar" }, el("span", {}, k), s, el("span", { class: "c" }, v));
    }));
  }
  function renderTrends() {
    const t = DATA.trends;
    $("trends").replaceChildren(
      el("h2", {}, "Exploited vulnerabilities added per week (CISA KEV)"), columnChart(t.kev_by_week, "KEV additions per week"),
      el("h2", {}, "Most active ransomware groups (latest leak-site posts)"), barList(t.top_groups),
      el("h2", {}, "Most targeted sectors"), barList(t.top_sectors),
      el("h2", {}, "Most active malware families (IOCs, 24 h)"), barList(t.top_malware));
  }

  // ------------------------------------------------------------------ page
  function renderHero() {
    const st = DATA.stats;
    $("updated").textContent = "Updated " + ago(DATA.generated);
    $("heroN").textContent = st.kev_7d;
    $("heroL").textContent = `actively exploited flaw${st.kev_7d === 1 ? "" : "s"} added this week`;
    $("dot").classList.toggle("calm", st.kev_7d === 0);
    $("sX").textContent = st.exploited_30d;
    $("sRw").textContent = st.ransomware_linked;
    $("sV").textContent = region === "sa" ? st.victims_south_asia : st.victims;
    $("sVl").textContent = region === "sa" ? "South Asia leak claims" : "Leak-site claims";
    $("sI").textContent = st.iocs_24h;
    const list = victims().slice(0, 25);
    $("ticker").hidden = !list.length;
    $("track").replaceChildren(...list.map(r => el("span", {}, el("em", {}, r.group),
      `${r.victim}${r.country ? " (" + r.country + ")" : ""}   ·   `)));
    $("status").replaceChildren(...Object.entries(DATA.source_status || {}).map(([k, v]) =>
      el("span", { title: v.ok ? "OK" : "Failed on last refresh: " + (v.error || "") }, el("i", { class: v.ok ? "" : "bad" }), k)));
  }
  function renderAll() { renderHero(); renderVulns(); renderRansom(); renderIntel(); renderTrends(); }

  function wire() {
    document.querySelectorAll("nav button").forEach(b => b.addEventListener("click", () => {
      document.querySelectorAll("nav button").forEach(x => x.setAttribute("aria-selected", String(x === b)));
      ["vulns", "ransom", "intel", "trends"].forEach(id => { $(id).hidden = id !== b.dataset.tab; });
    }));
    document.querySelectorAll(".region button").forEach(b => b.addEventListener("click", () => {
      region = b.dataset.region; store.set("tp-region", region);
      document.querySelectorAll(".region button").forEach(x => x.setAttribute("aria-pressed", String(x === b)));
      if (DATA) { renderHero(); renderRansom(); renderIntel(); }
    }));
    document.querySelectorAll(".region button").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.region === region)));
    $("watch").value = store.get("tp-watch") || "";
    $("watch").addEventListener("input", () => { store.set("tp-watch", $("watch").value); if (DATA) renderVulns(); });
    $("q").addEventListener("input", () => DATA && renderVulns());
    $("pf").addEventListener("change", () => DATA && renderVulns());
  }

  async function load() {
    try {
      const inline = document.getElementById("tp-data");  // used only by the static preview build
      // GitHub Pages / Cloudflare Pages serve data.json; Cloud Run serves api/data.
      let r = inline ? null : await fetch("data.json", { cache: "no-cache" });
      if (r && !r.ok) r = await fetch("api/data", { cache: "no-cache" });
      if (r && r.status === 503) { $("updated").textContent = "First refresh running…"; setTimeout(load, 30000); return; }
      if (r && !r.ok) throw new Error(String(r.status));
      DATA = inline ? JSON.parse(inline.textContent) : await r.json();
      renderAll();
    } catch (e) {
      $("updated").textContent = "Data unavailable";
    }
  }

  wire(); load();
  setInterval(() => { if (!document.hidden && !document.getElementById("tp-data")) load(); }, 10 * 60 * 1000);
})();
