"use strict";
// ThreatPulse front end.
// Security: feed data is untrusted. The DOM is built with textContent only (never innerHTML),
// and only http(s) links are rendered.
(() => {
  // ------------------------------------------------------------------ helpers
  const SVG = "http://www.w3.org/2000/svg";
  const $ = id => document.getElementById(id);
  const $$ = sel => Array.from(document.querySelectorAll(sel));
  const el = (tag, attrs = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") n.className = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids.flat(Infinity)) if (k !== null && k !== undefined && k !== false && k !== "") n.append(k instanceof Node ? k : String(k));
    return n;
  };
  const svg = (tag, attrs = {}, ...kids) => {
    const n = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    for (const k of kids) n.append(k instanceof Node ? k : document.createTextNode(String(k)));
    return n;
  };
  const safeUrl = u => (typeof u === "string" && /^https?:\/\//i.test(u)) ? u : null;
  const ext = (u, text, cls) => safeUrl(u) ? el("a", { href: u, target: "_blank", rel: "noopener noreferrer", class: cls }, text) : el("span", {}, text);
  const host = u => { try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return u; } };
  const fmt = n => n >= 1e9 ? (n / 1e9).toFixed(1) + "B" : n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? Math.round(n / 1e3) + "K" : String(n);
  const DAY = 864e5;
  const today = () => new Date(new Date().toISOString().slice(0, 10)).getTime();
  const daysFrom = d => d ? Math.round((Date.parse(d.slice(0, 10)) - today()) / DAY) : null;
  const ago = iso => {
    const m = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 6e4));
    return m < 1 ? "just now" : m < 60 ? `${m} min ago` : m < 1440 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} d ago`;
  };
  const relDay = d => { const n = daysFrom(d); return n === null || isNaN(n) ? "" : n === 0 ? "today" : n === -1 ? "yesterday" : n < 0 ? `${-n} days ago` : `in ${n} days`; };
  const defang = s => String(s).replace(/^http/i, "hxxp").replace(/\./g, "[.]");
  const regionName = (() => { try { const dn = new Intl.DisplayNames(["en"], { type: "region" }); return c => { try { return c ? dn.of(c) : ""; } catch { return c; } }; } catch { return c => c; } })();
  const store = {
    get: k => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  };
  let toastT;
  const toast = msg => { const t = $("toast"); t.textContent = msg; t.classList.add("show"); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove("show"), 1600); };
  const copy = async (text, label) => { try { await navigator.clipboard.writeText(text); toast(`Copied ${label}`); } catch { toast("Copy not allowed here"); } };

  // ------------------------------------------------------------------ state
  let DATA = null;
  const S = {
    tab: "vulns", region: store.get("tp-region") === "sa" ? "sa" : "global",
    chip: "all", q: "", sort: "priority", vLimit: 20, rq: "", rg: "", rLimit: 60,
  };
  const watchList = () => $("watch").value.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  const isWatched = v => v.watch || watchList().some(w => `${v.vendor} ${v.product} ${v.title}`.toLowerCase().includes(w));
  const PR = { P1: 0, P2: 1, P3: 2, P4: 3 };
  const TABS = ["vulns", "ransomware", "outages", "intel", "trends"];

  // ------------------------------------------------------------------ vulnerabilities
  function vulnRows() {
    const q = S.q.toLowerCase();
    let rows = DATA.vulns.filter(v => {
      if (S.chip === "kev" && !v.kev) return false;
      if (S.chip === "ransomware" && !v.ransomware) return false;
      if (S.chip === "watch" && !isWatched(v)) return false;
      if (/^P\d$/.test(S.chip) && v.priority !== S.chip) return false;
      return !q || `${v.id} ${v.title} ${v.vendor} ${v.product} ${v.name || ""}`.toLowerCase().includes(q);
    });
    const by = {
      priority: (a, b) => PR[a.priority] - PR[b.priority] || (b.date || "").localeCompare(a.date || ""),
      newest: (a, b) => (b.date || "").localeCompare(a.date || ""),
      due: (a, b) => (a.due || "9999").localeCompare(b.due || "9999"),
      epss: (a, b) => (b.epss || 0) - (a.epss || 0),
    }[S.sort];
    rows = rows.sort(by).sort((a, b) => isWatched(b) - isWatched(a)); // your stack first, stable
    return rows;
  }

  function dueBadge(v) {
    if (!v.due) return null;
    const n = daysFrom(v.due);
    const cls = n < 0 ? "b hot" : n <= 3 ? "b warn" : "b";
    const txt = n < 0 ? `Overdue ${-n}d` : n === 0 ? "Due today" : `Due in ${n}d`;
    return el("span", { class: cls, title: `CISA deadline ${v.due}` }, txt);
  }

  function card(v) {
    const ai = v.ai || {};
    const advisory = (v.links || []).map(safeUrl).find(Boolean);
    const more = el("details", { class: "more" }, el("summary", {}, "Details, sources & news"),
      ai.who && el("p", {}, el("b", {}, "Who's at risk: "), ai.who),
      ai.prevent && ai.prevent.length > 0 && [el("p", {}, el("b", {}, "How to prevent")), el("ul", {}, ai.prevent.map(s => el("li", {}, s)))],
      ai.what && v.summary && el("p", { class: "fix" }, el("b", {}, "Technical: "), v.summary),
      v.name && el("p", { class: "fix" }, v.name),
      v.fix_full && el("p", { class: "fix" }, el("b", {}, "CISA required action: "), v.fix_full),
      el("ul", {},
        (v.links || []).filter(safeUrl).map(u => el("li", {}, ext(u, host(u)))),
        (v.news || []).filter(n => safeUrl(n.link)).map(n => el("li", {}, ext(n.link, `${n.source}: ${n.title}`)))));
    return el("article", { class: "card " + v.priority, id: "v-" + v.id },
      el("div", { class: "row" },
        el("span", { class: "b " + v.priority, title: { P1: "Patch now", P2: "Patch this week", P3: "Plan the patch", P4: "Watch" }[v.priority] }, v.priority),
        isWatched(v) && el("span", { class: "b star" }, "★ Your stack"),
        v.kev && el("span", { class: "b hot", title: "Confirmed exploited in the wild (CISA KEV)" }, "Exploited"),
        v.ransomware && el("span", { class: "b hot", title: "Used in ransomware campaigns" }, "Ransomware"),
        v.epss >= 0.01 && el("span", { class: v.epss >= 0.5 ? "b warn" : "b", title: "Chance of exploitation in the next 30 days (EPSS)" }, `EPSS ${Math.round(v.epss * 100)}%`),
        v.cvss > 0 && el("span", { class: "b", title: "Severity score (CVSS)" }, `CVSS ${v.cvss}`),
        dueBadge(v),
        el("span", { class: "id" }, v.id)),
      el("h4", {}, v.title),
      el("p", { class: "sum" }, ai.what || v.summary),
      el("p", { class: "fix" }, el("b", {}, "Fix: "), v.fix, v.date ? ` · Added ${relDay(v.date)}` : ""),
      el("div", { class: "actions" },
        advisory && ext(advisory, "Open advisory ↗", "btn"),
        el("button", { class: "btn", type: "button", onclick: () => copy(v.id, v.id) }, "Copy CVE")),
      more);
  }

  function renderVulns() {
    const all = vulnRows();
    const rows = all.slice(0, S.vLimit);
    $("list").replaceChildren(...(rows.length ? rows.map(card) : [el("div", { class: "empty" },
      S.chip === "watch" ? (watchList().length ? "Nothing on your stack right now. Good news." : "Set your stack above to use this filter.") : "Nothing matches these filters.")]));
    $("vCount").textContent = `Showing ${rows.length} of ${all.length}` + (all.length !== DATA.vulns.length ? ` (filtered from ${DATA.vulns.length})` : "");
    $("moreV").hidden = all.length <= S.vLimit;
    $("clear").hidden = S.chip === "all" && !S.q;
    $$(".chip").forEach(c => c.setAttribute("aria-pressed", String(c.dataset.chip === S.chip)));
    const w = watchList();
    $("stackLabel").textContent = w.length ? `Your stack: ${w.join(", ")}` : "Set your stack";
  }

  // ------------------------------------------------------------------ ransomware
  const victims = () => DATA.ransomware.filter(v => S.region === "global" || v.south_asia);

  function renderRansom() {
    const q = S.rq.toLowerCase();
    const all = victims().filter(r => (!S.rg || r.group === S.rg) &&
      (!q || `${r.victim} ${r.sector} ${r.country} ${regionName(r.country)} ${r.domain} ${r.group}`.toLowerCase().includes(q)));
    const rows = all.slice(0, S.rLimit);
    $("rCount").textContent = `${all.length} claim${all.length === 1 ? "" : "s"}${S.region === "sa" ? " in South Asia" : ""}`;
    $("moreR").hidden = all.length <= S.rLimit;
    if (!rows.length) {
      $("rlist").replaceChildren(el("div", { class: "empty" }, S.region === "sa" && !q && !S.rg
        ? "No South Asian organisations in the latest leak-site posts." : "No claims match."));
      return;
    }
    const kids = []; let lastDay = null;
    for (const r of rows) {
      if (r.date !== lastDay) {
        lastDay = r.date;
        const rel = relDay(r.date);
        kids.push(el("div", { class: "day" }, rel === "today" || rel === "yesterday" ? `${rel} · ${r.date}` : r.date || "Date unknown"));
      }
      kids.push(el("div", { class: "v" },
        el("div", {}, el("b", {}, r.victim), el("br"),
          el("small", {}, [r.sector, regionName(r.country), r.domain && r.domain !== r.victim ? host(r.domain) : ""].filter(Boolean).join(" · "))),
        el("div", { class: "r" }, el("b", {}, r.group), " ",
          r.sources && r.sources.length > 1 ? el("span", { class: "b ok", title: r.sources.join(" + ") }, "2 trackers") : null)));
    }
    $("rlist").replaceChildren(el("div", { class: "list" }, kids));
  }

  function fillGroups() {
    const counts = {};
    victims().forEach(v => { counts[v.group] = (counts[v.group] || 0) + 1; });
    const sel = $("rg"), cur = S.rg;
    sel.replaceChildren(el("option", { value: "" }, "All groups"),
      ...Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([g, n]) => el("option", { value: g }, `${g} (${n})`)));
    sel.value = counts[cur] ? cur : "";
    S.rg = sel.value;
  }

  // ------------------------------------------------------------------ outages
  const STATE_LABEL = { up: "Operational", degraded: "Degraded", down: "Outage", maintenance: "Maintenance", unknown: "No data", warn: "Warning" };

  function strip(hist) {
    const n = 48, w = 6, gap = 2, H = 18;
    const s = svg("svg", { viewBox: `0 0 ${n * (w + gap) - gap} ${H}`, class: "strip", preserveAspectRatio: "none", "aria-hidden": "true" });
    const pad = n - hist.length;
    for (let i = 0; i < n; i++) {
      const h = hist[i - pad];
      const r = svg("rect", { x: i * (w + gap), y: 0, width: w, height: H, rx: 1.5, class: h ? h.s : "" });
      if (h) r.append(svg("title", {}, `${new Date(h.t).toLocaleString()} — ${STATE_LABEL[h.s] || h.s}${h.ms ? ` · ${h.ms} ms` : ""}`));
      s.append(r);
    }
    return s;
  }

  function svcTile(s) {
    return el("div", { class: "svc " + s.state },
      el("div", { class: "h" }, el("span", { class: "sdot " + s.state, "aria-hidden": "true" }), ext(s.page, s.name),
        el("span", { class: "st " + s.state }, STATE_LABEL[s.state] || s.state)),
      s.incident ? el("div", { class: "inc" }, ext(s.incident.link, s.incident.title || "View incident")) : el("div", { class: "d" }, s.detail),
      strip(s.history || []),
      el("div", { class: "f" }, el("span", {}, `${(s.history || []).length} h ago`), el("span", {}, s.uptime != null ? `${s.uptime}% up` : ""), el("span", {}, "now")));
  }

  function siteTile(s) {
    const certInDetail = /TLS/.test(s.detail || "");
    const bits = [s.code ? `HTTP ${s.code}` : null, s.ms != null ? `${s.ms} ms` : null, s.cert_days != null && !certInDetail ? `TLS cert ${s.cert_days}d left` : null].filter(Boolean).join(" · ");
    return el("div", { class: "svc " + s.state },
      el("div", { class: "h" }, el("span", { class: "sdot " + s.state, "aria-hidden": "true" }), ext(s.url, s.host),
        el("span", { class: "st " + s.state }, s.state === "up" ? "Up" : s.state === "down" ? "Down" : "Warning")),
      el("div", { class: "d" }, s.state === "up" ? bits : `${s.detail}${bits ? " · " + bits : ""}`),
      strip(s.history || []),
      el("div", { class: "f" }, el("span", {}, s.since ? `${STATE_LABEL[s.state] || s.state} since ${ago(s.since)}` : ""), el("span", {}, s.uptime != null ? `${s.uptime}% uptime` : "")));
  }

  function renderOutages() {
    const o = DATA.outages || { services: [], sites: [] };
    const bad = o.services.filter(s => s.state === "down"), meh = o.services.filter(s => s.state === "degraded");
    const sitesDown = o.sites.filter(s => s.state === "down");
    const cls = bad.length || sitesDown.length ? "bad" : meh.length ? "warn" : "ok";
    const head = sitesDown.length ? (sitesDown.length === 1 ? `Your site ${sitesDown[0].host} is down` : `${sitesDown.length} of your sites are down`)
      : bad.length ? `Major outage: ${bad.map(s => s.name).join(", ")}`
      : meh.length ? `${meh.length} service${meh.length > 1 ? "s" : ""} with issues: ${meh.map(s => s.name).join(", ")}`
      : "All major services operational";
    $("overall").replaceChildren(el("div", { class: "overall " + cls },
      el("span", { class: "sdot " + (cls === "ok" ? "up" : cls === "warn" ? "degraded" : "down"), "aria-hidden": "true" }),
      el("div", {}, head, el("small", {}, o.checked ? `Checked ${ago(o.checked)} · refreshed hourly from GitHub's servers` : "Not checked yet"))));

    $("sites").replaceChildren(o.sites.length ? el("div", { class: "grid" }, o.sites.map(siteTile)) :
      el("div", { class: "howto" }, el("b", {}, "Monitor your own websites"), " — get uptime, speed and TLS-expiry checks, plus Telegram alerts when one goes down.",
        el("ol", {},
          el("li", {}, "In your GitHub repo open Settings → Secrets and variables → Actions → Variables."),
          el("li", {}, "Add a variable named ", el("code", {}, "WATCH_SITES"), " with your sites, comma separated, e.g. ", el("code", {}, "mysite.lk, shop.example.com")),
          el("li", {}, "Results appear here after the next hourly run (or run the workflow now)."))));

    const cats = {};
    o.services.forEach(s => (cats[s.cat] = cats[s.cat] || []).push(s));
    const rank = { down: 0, degraded: 1, maintenance: 2, unknown: 4, up: 3 };
    $("services").replaceChildren(...Object.entries(cats).map(([c, list]) => [
      el("h3", { class: "sub" }, c),
      el("div", { class: "grid" }, list.sort((a, b) => rank[a.state] - rank[b.state]).map(svcTile))]).flat());
  }

  // ------------------------------------------------------------------ breaches & IOCs
  function renderIntel() {
    const kids = [el("h3", { class: "sub" }, "Newly disclosed data breaches")];
    kids.push(DATA.breaches.length ? el("div", { class: "list" }, DATA.breaches.slice(0, 12).map(b => el("div", { class: "v" },
      el("div", {}, ext(b.link, b.title), b.verified ? el("span", { class: "b ok", title: "Verified by Have I Been Pwned" }, " verified") : null, el("br"),
        el("small", {}, b.data.join(", "))),
      el("div", { class: "r" }, el("b", {}, fmt(b.count) + " accounts"), el("br"), el("small", {}, `breached ${b.breach_date}`)))))
      : el("div", { class: "empty" }, "Breach feed fills in on the next refresh."));

    kids.push(el("h3", { class: "sub" }, "Fresh malicious indicators · last 24 h"),
      el("p", { class: "note" }, el("b", {}, "Defanged."), " Block these in your firewall, DNS or EDR. Don't visit them."));
    if (DATA.iocs.length) {
      kids.push(el("div", { class: "list" }, DATA.iocs.slice(0, 30).map(i => el("div", { class: "v" },
        el("div", {}, el("div", { class: "mono" }, defang(i.ioc)), el("small", {}, `${i.type} · ${i.threat.replace(/_/g, " ")}`)),
        el("div", { class: "r" }, el("b", {}, i.malware), el("br"), el("small", {}, `${i.confidence}% confidence `),
          el("button", { class: "linkbtn", type: "button", onclick: () => copy(defang(i.ioc), "indicator") }, "copy"))))));
    } else kids.push(el("div", { class: "empty" }, "Add a free abuse.ch Auth-Key (ABUSECH_AUTH_KEY secret) to switch on live indicators."));

    const news = DATA.news.filter(n => safeUrl(n.link) && (S.region === "global" || n.south_asia));
    kids.push(el("h3", { class: "sub" }, S.region === "sa" ? "South Asia headlines" : "Headlines"));
    kids.push(news.length ? el("div", { class: "list" }, news.slice(0, 15).map(n => el("div", { class: "v" },
      el("div", {}, ext(n.link, n.title)), el("div", { class: "r" }, el("small", {}, n.source)))))
      : el("div", { class: "empty" }, "No matching headlines right now."));
    $("intel").replaceChildren(...kids);
  }

  // ------------------------------------------------------------------ trends
  function columnChart(obj, label) {
    const keys = Object.keys(obj); if (!keys.length) return el("div", { class: "empty" }, "Not enough data yet.");
    const W = 720, H = 170, top = 22, max = Math.max(...Object.values(obj)), bw = (W - 8 * (keys.length - 1)) / keys.length;
    const g = svg("svg", { viewBox: `0 0 ${W} ${H + 18}`, class: "chart", role: "img", "aria-label": label });
    keys.forEach((k, i) => {
      const h = Math.max(2, (obj[k] / max) * (H - top)), x = i * (bw + 8), y = H - h;
      g.append(svg("rect", { class: "bar", x, y, width: bw, height: h, rx: 3 }),
        svg("text", { x: x + bw / 2, y: y - 6, "text-anchor": "middle" }, obj[k]),
        svg("text", { x: x + bw / 2, y: H + 14, "text-anchor": "middle" }, k.split("-")[1] || k));
    });
    return g;
  }
  function barList(obj) {
    const e = Object.entries(obj || {}); if (!e.length) return el("div", { class: "empty" }, "Not enough data yet.");
    const max = Math.max(...e.map(x => x[1]));
    return el("div", {}, e.map(([k, v]) => el("div", { class: "hbar" }, el("span", { title: k }, k),
      svg("svg", { viewBox: "0 0 100 10", preserveAspectRatio: "none", "aria-hidden": "true" }, svg("rect", { x: 0, y: 0, height: 10, rx: 2, width: Math.max(2, (v / max) * 100) })),
      el("span", { class: "c" }, v))));
  }
  function renderTrends() {
    const t = DATA.trends;
    $("trends").replaceChildren(
      el("h3", { class: "sub" }, "Exploited vulnerabilities added per week"), el("div", { class: "card2" }, columnChart(t.kev_by_week, "CISA KEV additions per week")),
      el("h3", { class: "sub" }, "Most active ransomware groups"), el("div", { class: "card2" }, barList(t.top_groups)),
      el("h3", { class: "sub" }, "Most targeted sectors"), el("div", { class: "card2" }, barList(t.top_sectors)),
      el("h3", { class: "sub" }, "Most active malware families · 24 h"), el("div", { class: "card2" }, barList(t.top_malware)));
  }

  // ------------------------------------------------------------------ hero, banner, footer
  function renderHero() {
    const st = DATA.stats;
    $("updated").textContent = "Updated " + ago(DATA.generated);
    $("updated").title = new Date(DATA.generated).toLocaleString();
    $("heroN").textContent = st.kev_7d;
    $("heroN").classList.toggle("calm", st.kev_7d === 0);
    $("heroL").textContent = st.kev_7d === 0 ? "no new actively exploited flaws this week" : `actively exploited flaw${st.kev_7d === 1 ? "" : "s"} added this week`;
    $("dot").classList.toggle("calm", st.kev_7d === 0);
    $("sX").textContent = st.exploited_30d;
    $("sRw").textContent = st.ransomware_linked;
    const sa = S.region === "sa";
    $("sV").textContent = sa ? st.victims_south_asia : st.victims;
    $("sVl").textContent = sa ? "Leak claims · South Asia" : "Leak-site claims";
    const outN = (st.services_issues || 0) + (st.sites_down || 0);
    $("sO").textContent = DATA.outages ? outN : "–";
    $("tOut").className = "tile " + (outN ? "hot" : "good");

    // "Do this first": the P1 with the nearest CISA deadline, preferring your stack
    const p1 = DATA.vulns.filter(v => v.priority === "P1");
    const pick = p1.filter(isWatched).sort((a, b) => (a.due || "9").localeCompare(b.due || "9"))[0]
      || p1.filter(v => v.due && daysFrom(v.due) >= -3).sort((a, b) => a.due.localeCompare(b.due))[0] || p1[0];
    $("first").replaceChildren(pick ? el("div", { class: "first" },
      el("div", {}, el("div", { class: "k" }, isWatched(pick) ? "Do this first · on your stack" : "Do this first"),
        el("div", { class: "t" }, `Patch ${pick.title}`),
        el("small", {}, [pick.id, pick.due ? `CISA deadline ${pick.due} (${relDay(pick.due)})` : null, pick.ransomware ? "used by ransomware" : null].filter(Boolean).join(" · "))),
      el("button", { class: "btn primary", type: "button", onclick: () => jumpTo(pick.id) }, "See details")) : "");

    // counts on tabs
    const cv = $("cVulns"); cv.textContent = DATA.vulns.filter(v => v.priority === "P1").length; cv.className = "count hot"; cv.title = "P1 items";
    const cr = $("cRansom"); cr.textContent = victims().length; cr.className = "count";
    const co = $("cOut"); co.textContent = DATA.outages ? outN : ""; co.className = outN ? "count hot" : "count"; co.hidden = !DATA.outages;

    const list = victims().slice(0, 25);
    $("ticker").hidden = $("tickhead").hidden = !list.length;
    $("tickLabel").textContent = S.region === "sa" ? "Latest ransomware claims · South Asia" : "Latest ransomware leak-site claims";
    $("track").replaceChildren(...list.map(r => el("span", {}, el("em", {}, r.group),
      `${r.victim}${r.country ? " (" + r.country + ")" : ""}   ·   `)));
  }

  function renderBanner() {
    const age = (Date.now() - Date.parse(DATA.generated)) / 36e5;
    const failed = Object.entries(DATA.source_status || {}).filter(([, v]) => !v.ok).map(([k]) => k);
    const msgs = [];
    if (age > 3) msgs.push(el("div", { class: "banner warn", role: "status" }, `Data is ${Math.round(age)} hours old — the hourly refresh may be paused. Numbers below may be out of date.`));
    if (failed.length) msgs.push(el("div", { class: "banner", role: "status" }, `Some feeds didn't respond on the last refresh (${failed.join(", ")}). Showing their last good data.`));
    $("banner").replaceChildren(...msgs);
    $("status").replaceChildren(...Object.entries(DATA.source_status || {}).map(([k, v]) =>
      el("span", { title: v.ok ? `OK (${v.seconds}s)` : "Failed on last refresh" }, el("i", { class: v.ok ? "" : "bad" }), k)));
  }

  function renderAll() { renderBanner(); renderHero(); renderVulns(); fillGroups(); renderRansom(); renderOutages(); renderIntel(); renderTrends(); }

  // ------------------------------------------------------------------ navigation
  function show(tab, scroll) {
    if (!TABS.includes(tab)) tab = "vulns";
    S.tab = tab;
    TABS.forEach(t => { $("p-" + t).hidden = t !== tab; });
    $$("nav.tabs a").forEach(a => { if (a.dataset.tab === tab) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
    if (scroll) $("p-" + tab).scrollIntoView({ block: "start" });
  }
  function jumpTo(id) {
    S.chip = "all"; S.q = ""; $("q").value = ""; S.vLimit = Math.max(S.vLimit, DATA.vulns.length);
    renderVulns(); location.hash = "#vulns"; show("vulns");
    const c = document.getElementById("v-" + id);
    if (c) { c.scrollIntoView({ block: "center" }); c.classList.remove("flash"); void c.offsetWidth; c.classList.add("flash"); const d = c.querySelector("details"); if (d) d.open = true; }
  }

  function wire() {
    window.addEventListener("hashchange", () => show(location.hash.slice(1), true));
    $$(".tile").forEach(t => t.addEventListener("click", () => {
      if (t.dataset.chip) { S.chip = t.dataset.chip; S.vLimit = 20; if (DATA) renderVulns(); }
      if (location.hash === "#" + t.dataset.go) show(t.dataset.go, true); else location.hash = "#" + t.dataset.go;
    }));
    $$(".chip").forEach(c => c.addEventListener("click", () => {
      S.chip = c.dataset.chip; S.vLimit = 20;
      if (S.chip === "watch" && !watchList().length) $("stackBox").open = true;
      if (DATA) renderVulns();
    }));
    $("q").addEventListener("input", e => { S.q = e.target.value.trim(); S.vLimit = 20; if (DATA) renderVulns(); });
    $("sort").addEventListener("change", e => { S.sort = e.target.value; if (DATA) renderVulns(); });
    $("clear").addEventListener("click", () => { S.chip = "all"; S.q = ""; $("q").value = ""; renderVulns(); });
    $("moreV").addEventListener("click", () => { S.vLimit += 20; renderVulns(); });
    $("watch").value = store.get("tp-watch") || "";
    if ($("watch").value) $("stackBox").open = false;
    $("watch").addEventListener("input", () => { store.set("tp-watch", $("watch").value); if (DATA) { renderVulns(); renderHero(); } });
    $("rq").addEventListener("input", e => { S.rq = e.target.value.trim(); S.rLimit = 60; if (DATA) renderRansom(); });
    $("rg").addEventListener("change", e => { S.rg = e.target.value; S.rLimit = 60; if (DATA) renderRansom(); });
    $("moreR").addEventListener("click", () => { S.rLimit += 60; renderRansom(); });

    $$(".seg button").forEach(b => b.addEventListener("click", () => {
      S.region = b.dataset.region; store.set("tp-region", S.region);
      $$(".seg button").forEach(x => x.setAttribute("aria-pressed", String(x === b)));
      if (DATA) { renderHero(); fillGroups(); renderRansom(); renderIntel(); }
    }));
    $$(".seg button").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.region === S.region)));

    $("theme").addEventListener("click", () => {
      const root = document.documentElement;
      const dark = root.dataset.theme ? root.dataset.theme === "dark" : !matchMedia("(prefers-color-scheme: light)").matches;
      root.dataset.theme = dark ? "light" : "dark"; store.set("tp-theme", root.dataset.theme);
      toast(dark ? "Light mode" : "Dark mode");
    });
    const dlg = $("glossary");
    $("help").addEventListener("click", () => (dlg.showModal ? dlg.showModal() : dlg.setAttribute("open", "")));
    $("gClose").addEventListener("click", () => dlg.close());
    dlg.addEventListener("click", e => { if (e.target === dlg) dlg.close(); });

    document.addEventListener("keydown", e => {
      if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) {
        e.preventDefault(); location.hash = "#vulns"; show("vulns"); $("q").focus();
      }
    });
    const top = $("totop");
    window.addEventListener("scroll", () => top.classList.toggle("show", scrollY > 800), { passive: true });
    top.addEventListener("click", () => scrollTo({ top: 0 }));
    show(location.hash.slice(1) || "vulns");
  }

  // ------------------------------------------------------------------ data
  async function load() {
    try {
      const inline = document.getElementById("tp-data");  // static preview build only
      let r = inline ? null : await fetch("data.json", { cache: "no-cache" });
      if (r && !r.ok) r = await fetch("api/data", { cache: "no-cache" });  // Cloud Run variant
      if (r && r.status === 503) { $("updated").textContent = "First refresh running…"; setTimeout(load, 30000); return; }
      if (r && !r.ok) throw new Error(String(r.status));
      DATA = inline ? JSON.parse(inline.textContent) : await r.json();
      DATA.vulns = DATA.vulns || []; DATA.ransomware = DATA.ransomware || []; DATA.breaches = DATA.breaches || [];
      DATA.iocs = DATA.iocs || []; DATA.news = DATA.news || []; DATA.trends = DATA.trends || {};
      renderAll();
    } catch (e) {
      $("updated").textContent = "Data unavailable";
      $("list").replaceChildren(el("div", { class: "empty" }, "Couldn't load the latest data. Try refreshing in a minute."));
    }
  }

  wire(); load();
  setInterval(() => { if (!document.hidden && !document.getElementById("tp-data")) load(); }, 10 * 60 * 1000);
  setInterval(() => { if (DATA) $("updated").textContent = "Updated " + ago(DATA.generated); }, 60 * 1000);
})();
