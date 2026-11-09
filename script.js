(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const NS = "http://www.w3.org/2000/svg";
  const ITERATIONS = 310000;
  const te = new TextEncoder(), td = new TextDecoder();

  // ---------------- state ----------------
  let file = null;          // the encrypted data.json object (users block reused when saving)
  let dataKey = null;       // CryptoKey used to encrypt the events
  let dataKeyRaw = null;    // raw bytes of the data key (needed to change passwords)
  let role = null;          // "admin" | "viewer"
  let events = [];
  let selectedId = null;
  let editingId = null;
  let dirty = false;

  // ---------------- crypto helpers ----------------
  function b64(buf) {
    const bytes = new Uint8Array(buf); let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

  async function passwordKey(password, salt, iterations) {
    const base = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function wrapFor(password, raw) {
    const salt = rand(16), iv = rand(12);
    const kek = await passwordKey(password, salt, ITERATIONS);
    const key = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, raw);
    return { salt: b64(salt), iv: b64(iv), key: b64(key) };
  }
  async function importDataKey(raw) {
    return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }

  // ---------------- data file ----------------
  async function fetchDataFile() {
    if (location.protocol === "file:") return { status: "local" };
    try {
      const r = await fetch("data.json", { cache: "no-store" });
      if (r.status === 404) return { status: "missing" };
      if (!r.ok) return { status: "error" };
      return { status: "ok", json: await r.json() };
    } catch { return { status: "error" }; }
  }
  function validFile(j) { return j && j.format === "life-line-v1" && j.users && j.iv && j.data; }

  async function buildFileJson() {
    const iv = rand(12);
    const payload = te.encode(JSON.stringify({ events, updatedAt: new Date().toISOString() }));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dataKey, payload);
    return { format: "life-line-v1", kdf: { name: "PBKDF2", hash: "SHA-256", iterations: ITERATIONS }, users: file.users, iv: b64(iv), data: b64(ct) };
  }

  function download(name, text) {
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = document.createElement("a"); a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // ---------------- login / setup ----------------
  const showErr = (el, msg) => { el.textContent = msg; el.hidden = !msg; };

  async function boot() {
    if (!window.crypto || !crypto.subtle) {
      showErr($("loginErr"), "This browser can't open encrypted files. Open the page over https.");
      return;
    }
    const res = await fetchDataFile();
    if (res.status === "ok" && validFile(res.json)) { file = res.json; }
    else if (res.status === "missing") { showSetup(); }
    else if (res.status === "local") { $("filePick").hidden = false; $("toSetup").hidden = false; }
    else if (res.status === "ok") { showErr($("loginErr"), "data.json is not a Life Line file."); $("toSetup").hidden = false; }
    else { showErr($("loginErr"), "Couldn't load data.json. Check your connection and reload."); }
  }
  function showSetup() { $("loginForm").hidden = true; $("setupForm").hidden = false; $("setAdmin").focus(); }
  $("toSetup").addEventListener("click", showSetup);

  $("dataFile").addEventListener("change", async () => {
    const f = $("dataFile").files[0]; if (!f) return;
    try {
      const j = JSON.parse(await f.text());
      if (!validFile(j)) throw 0;
      file = j; showErr($("loginErr"), "");
    } catch { file = null; showErr($("loginErr"), "This is not a Life Line data file."); }
  });

  $("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("loginErr");
    if (!file) { showErr(err, location.protocol === "file:" ? "Choose your data.json first." : "No data file loaded."); return; }
    const name = $("name").value.trim().toLowerCase();
    const pass = $("pass").value;
    const u = file.users[name];
    $("openBtn").disabled = true; showErr(err, "");
    try {
      if (!u || !pass) throw 0;
      const kek = await passwordKey(pass, unb64(u.salt), (file.kdf && file.kdf.iterations) || ITERATIONS);
      const raw = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(u.iv) }, kek, unb64(u.key)));
      const key = await importDataKey(raw);
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(file.iv) }, key, unb64(file.data));
      const data = JSON.parse(td.decode(plain));
      dataKey = key; dataKeyRaw = raw; role = name === "admin" ? "admin" : "viewer";
      events = normalize(data.events || []);
      $("pass").value = "";
      openApp();
      if (role === "admin") await initGitHub(pass);
    } catch {
      showErr(err, "Wrong name or password.");
    } finally { $("openBtn").disabled = false; }
  });

  $("setupForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const a = $("setAdmin").value, v = $("setViewer").value, err = $("setupErr");
    if (a.length < 2 || v.length < 2) { showErr(err, "Use at least 2 characters for each password."); return; }
    showErr(err, "");
    dataKeyRaw = rand(32);
    dataKey = await importDataKey(dataKeyRaw);
    file = { users: { admin: await wrapFor(a, dataKeyRaw), viewer: await wrapFor(v, dataKeyRaw) } };
    role = "admin"; events = []; setDirty(true);
    $("setAdmin").value = ""; $("setViewer").value = "";
    openApp();
    await initGitHub(a);
    if (!gh) notice("Press “GitHub” to turn on autosave, or add events and press “Save file”.");
  });

  function openApp() {
    $("loginView").hidden = true; $("appView").hidden = false;
    document.querySelectorAll(".admin-only").forEach((el) => { if (role !== "admin") el.hidden = true; else if (!el.classList.contains("toggle")) el.hidden = false; });
    updateSyncUi();
    document.querySelectorAll(".viewer-only").forEach((el) => el.hidden = role === "admin");
    resetForm(); render();
  }

  $("logoutBtn").addEventListener("click", () => {
    if (dirty && !$("logoutBtn").classList.contains("armed")) {
      $("logoutBtn").classList.add("armed"); $("logoutBtn").textContent = "Unsaved changes. Log out?";
      setTimeout(() => { $("logoutBtn").classList.remove("armed"); $("logoutBtn").textContent = "Log out"; }, 4000);
      return;
    }
    dirty = false;
    location.reload();
  });

  // ---------------- helpers ----------------
  function normalize(list) {
    return list.filter((e) => e && Number.isFinite(+e.age) && String(e.title || "").trim()).map((e) => ({
      id: typeof e.id === "string" && e.id ? e.id : newId(),
      age: +e.age,
      title: String(e.title).trim().slice(0, 80),
      emotion: Number.isFinite(+e.emotion) && e.emotion !== null ? Math.max(-5, Math.min(5, Math.round(+e.emotion))) : 0,
      note: typeof e.note === "string" ? e.note : ""
    }));
  }
  const newId = () => (crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2));
  // By age; events from the same age keep the order they were added in.
  const sorted = () => [...events].sort((a, b) => a.age - b.age);
  const fmtAge = (a) => String(Math.round(a * 10) / 10);
  const fmtEmo = (v) => v > 0 ? "+" + v : v < 0 ? "−" + Math.abs(v) : "0";
  const emoClass = (v) => v > 0 ? "good" : v < 0 ? "bad" : "zero";
  const trunc = (s, n) => s.length > n ? s.slice(0, n - 1) + "…" : s;

  let changes = 0;
  function setDirty(v) {
    dirty = v;
    if (v) changes++;
    $("saveBtn").classList.toggle("dirty", v);
    $("saveBtn").textContent = v ? "Save file •" : "Save file";
    if (v && gh) scheduleSync();
  }
  window.addEventListener("beforeunload", (e) => { if (dirty) { e.preventDefault(); e.returnValue = ""; } });

  let noticeTimer = null;
  function notice(msg, ms = 0) {
    const n = $("notice"); n.replaceChildren(document.createTextNode(msg)); n.hidden = false;
    clearTimeout(noticeTimer); if (ms) noticeTimer = setTimeout(() => n.hidden = true, ms);
  }

  // ---------------- chart ----------------
  const W = 1000, H = 420, L = 50, R = 24, T = 30, B = 50;
  const yMid = T + (H - T - B) / 2;
  const yOf = (v) => yMid - v * ((H - T - B) / 2) / 5;
  const el = (tag, attrs = {}, text) => {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) {
      const v = attrs[k];
      if ((k === "fill" || k === "stroke") && typeof v === "string" && v.startsWith("var(")) n.style.setProperty(k, v);
      else n.setAttribute(k, v);
    }
    if (text != null) n.textContent = text;
    return n;
  };
  let xOf = (a) => a;
  let ptX = new Map();      // event id -> x on the chart (same-age events sit side by side)
  const SPREAD = 22;

  function drawChart() {
    const svg = $("chart"); svg.replaceChildren();
    const list = sorted();
    // The axis ends exactly at the oldest event's age (0–10 when there are no events yet).
    const maxAge = list.length ? Math.max(1, ...list.map((e) => e.age)) : 10;
    const step = maxAge > 50 ? 10 : maxAge > 12 ? 5 : maxAge > 4 ? 2 : 1;
    xOf = (a) => L + (a / maxAge) * (W - L - R);

    const groups = new Map();
    for (const e of list) { if (!groups.has(e.age)) groups.set(e.age, []); groups.get(e.age).push(e); }
    ptX = new Map();
    for (const [age, g] of groups) {
      const half = (g.length - 1) / 2 * SPREAD;
      const mid = Math.min(Math.max(xOf(age), L + half), W - R - half);
      g.forEach((e, i) => ptX.set(e.id, mid - half + i * SPREAD));
    }
    const px = (e) => ptX.get(e.id);

    const defs = el("defs");
    const cu = el("clipPath", { id: "clipUp" }); cu.append(el("rect", { x: 0, y: 0, width: W, height: yMid }));
    const cd = el("clipPath", { id: "clipDown" }); cd.append(el("rect", { x: 0, y: yMid, width: W, height: H }));
    defs.append(cu, cd); svg.append(defs);

    for (const v of [5, -5]) svg.append(el("line", { x1: L, x2: W - R, y1: yOf(v), y2: yOf(v), stroke: "var(--grid)" }));

    if (list.length) {
      const pts = list.map((e) => [px(e), yOf(e.emotion)]);
      const d = `M${pts[0][0]},${yMid} ` + pts.map((p) => `L${p[0]},${p[1]}`).join(" ") + ` L${pts[pts.length - 1][0]},${yMid} Z`;
      svg.append(el("path", { d, fill: "var(--good-soft)", "clip-path": "url(#clipUp)" }));
      svg.append(el("path", { d, fill: "var(--bad-soft)", "clip-path": "url(#clipDown)" }));
    }
    svg.append(el("line", { x1: L, x2: W - R, y1: yMid, y2: yMid, stroke: "var(--axis)", "stroke-width": 1.5 }));
    [[5, "+5"], [0, "0"], [-5, "−5"]].forEach(([v, t]) => svg.append(el("text", { x: L - 10, y: yOf(v) + 4, "text-anchor": "end", "font-size": 12, fill: "var(--muted)" }, t)));

    if (list.length) {
      svg.append(el("polyline", { points: list.map((e) => `${px(e)},${yOf(e.emotion)}`).join(" "), fill: "none", stroke: "var(--accent)", "stroke-width": 2.5, "stroke-linejoin": "round" }));
    }

    // x axis
    const yAx = H - B + 8;
    svg.append(el("line", { x1: L, x2: W - R, y1: yAx, y2: yAx, stroke: "var(--axis)" }));
    // Regular ticks, then the last age itself; skip a regular tick that would crowd it.
    for (let a = 0; a < maxAge - step * 0.3; a += step) {
      svg.append(el("text", { x: xOf(a), y: yAx + 20, "text-anchor": "middle", "font-size": 12, fill: "var(--muted)" }, String(a)));
    }
    svg.append(el("text", { x: xOf(maxAge), y: yAx + 20, "text-anchor": "middle", "font-size": 12, fill: "var(--muted)" }, fmtAge(maxAge)));
    svg.append(el("text", { x: W - R, y: H - 2, "text-anchor": "end", "font-size": 12, fill: "var(--muted)" }, "Age"));

    // points + vertical labels, so events close together don't cover each other's names.
    // A label runs up from its point (or down, when there's more room below) and is
    // shortened to fit; it switches side if it would overlap a label right next to it.
    const placed = [], GAP = 14, CH = 7.2, yTop = 4, yBottom = yAx - 4;
    list.forEach((e) => {
      const cx = px(e), cy = yOf(e.emotion), sel = e.id === selectedId;
      const crowded = groups.get(e.age).length > 1;
      const g = el("g", { class: "pt", tabindex: 0, role: "button", "aria-label": `Age ${fmtAge(e.age)}: ${e.title}, emotion ${fmtEmo(e.emotion)}` });
      g.append(el("circle", { cx, cy, r: crowded ? SPREAD / 2 : 16, fill: "transparent" }));
      g.append(el("circle", { cx, cy, r: sel ? 9 : 6, fill: sel ? "var(--accent)" : "#fff", stroke: sel ? "#fff" : "var(--accent)", "stroke-width": sel ? 3 : 2.5 }));
      const full = e.title.length * CH;
      const room = { up: cy - GAP - yTop, down: yBottom - (cy + GAP) };
      // Positive moments read upward, hard ones downward, unless that side is too short.
      const flip = (s) => s === "up" ? "down" : "up";
      let side = e.emotion < 0 ? "down" : "up";
      if (room[side] < full && room[flip(side)] > room[side]) side = flip(side);
      const span = (s) => { const len = Math.min(full, room[s]); return s === "up" ? [cy - GAP - len, cy - GAP] : [cy + GAP, cy + GAP + len]; };
      const hits = (s) => { const [a, b] = span(s); return placed.some((p) => Math.abs(p.x - cx) < 15 && p.a < b && a < p.b); };
      if (hits(side) && !hits(flip(side)) && room[flip(side)] > 40) side = flip(side);
      const [a, b] = span(side);
      placed.push({ x: cx, a, b });
      const label = trunc(e.title, Math.max(3, Math.floor(room[side] / CH)));
      // rotate(-90): text reads bottom-to-top; it starts at the point going up, or ends at it going down.
      const ty = side === "up" ? cy - GAP : cy + GAP;
      g.append(el("text", { x: cx, y: ty, transform: `rotate(-90 ${cx} ${ty})`, "text-anchor": side === "up" ? "start" : "end", "dominant-baseline": "central", "font-size": 13, "font-weight": 600, fill: "var(--ink)" }, label));
      g.addEventListener("click", () => select(e.id));
      g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); select(e.id); } });
      svg.append(g);
    });
    if (!list.length) {
      svg.append(el("text", { x: W / 2, y: yMid - 16, "text-anchor": "middle", "font-size": 14, fill: "var(--muted)" }, role === "admin" ? "Add your first life event" : "No events yet"));
    }
    drawPop();
  }

  function drawPop() {
    const pop = $("pop"), e = events.find((x) => x.id === selectedId);
    if (!e) { pop.hidden = true; return; }
    pop.hidden = false;
    $("popTitle").textContent = e.title;
    const meta = $("popMeta"); meta.replaceChildren(document.createTextNode(fmtAge(e.age) + " · "));
    const v = document.createElement("span"); v.className = emoClass(e.emotion); v.style.fontWeight = "600"; v.textContent = fmtEmo(e.emotion); meta.append(v);
    if (role === "admin") { if (document.activeElement !== $("popNote")) $("popNote").value = e.note; }
    else { $("popNoteText").textContent = e.note || ""; $("popNoteText").hidden = !e.note; }
    // position near the point (desktop); CSS makes it static on phones
    const cx = ptX.get(e.id) ?? xOf(e.age), cy = yOf(e.emotion);
    const leftPct = cx / W * 100, topPct = Math.min(Math.max(cy / H * 100 - 12, 0), 55);
    pop.style.top = topPct + "%";
    if (cx > W * 0.55) { pop.style.left = ""; pop.style.right = `calc(${100 - leftPct}% + 18px)`; }
    else { pop.style.right = ""; pop.style.left = `calc(${leftPct}% + 18px)`; }
  }
  $("popClose").addEventListener("click", () => { selectedId = null; render(); });
  let noteTimer = null;
  $("popNote").addEventListener("input", () => {
    const e = events.find((x) => x.id === selectedId); if (!e) return;
    e.note = $("popNote").value; setDirty(true);
    if (editingId === e.id) $("fNote").value = e.note;
    clearTimeout(noteTimer); noteTimer = setTimeout(drawList, 300);
  });

  // ---------------- list ----------------
  function drawList() {
    const box = $("rows"); box.replaceChildren();
    const list = sorted();
    if (!list.length) {
      const p = document.createElement("p"); p.className = "empty";
      p.textContent = role === "admin" ? "No events yet." : "No events yet.";
      box.append(p); return;
    }
    list.forEach((e, i) => {
      const item = document.createElement("div"); item.className = "item";
      const b = document.createElement("button"); b.type = "button"; b.className = "row" + (e.id === selectedId ? " active" : "");
      const a = document.createElement("span"); a.className = "age"; a.textContent = fmtAge(e.age);
      const t = document.createElement("span"); t.className = "t"; t.textContent = e.title;
      const v = document.createElement("span"); v.className = "v " + emoClass(e.emotion); v.textContent = fmtEmo(e.emotion);
      b.append(a, t, v);
      b.addEventListener("click", () => select(e.id));
      item.append(b);
      // Several events at the same age: the admin can set their order with ↑ / ↓.
      const prevSame = list[i - 1] && list[i - 1].age === e.age, nextSame = list[i + 1] && list[i + 1].age === e.age;
      if (role === "admin" && (prevSame || nextSame)) {
        const m = document.createElement("div"); m.className = "move";
        for (const [dir, sym, label, ok] of [[-1, "▲", "Move earlier", prevSame], [1, "▼", "Move later", nextSame]]) {
          const mb = document.createElement("button"); mb.type = "button"; mb.textContent = sym;
          mb.title = label; mb.setAttribute("aria-label", `${label}: ${e.title}`); mb.dataset.move = e.id + ":" + dir;
          mb.disabled = !ok;
          mb.addEventListener("click", () => move(e.id, dir));
          m.append(mb);
        }
        item.append(m);
      }
      box.append(item);
      // Viewers have no edit form, so show the note right under the chosen event in the list too.
      if (role !== "admin" && e.id === selectedId && e.note) {
        const n = document.createElement("p"); n.className = "row-note"; n.textContent = e.note;
        box.append(n);
      }
    });
  }

  // Swap an event with its neighbour of the same age. The sort is stable, so the
  // order of the events array is the order shown in the list and on the chart.
  function move(id, dir) {
    const list = sorted(), i = list.findIndex((x) => x.id === id);
    const a = list[i], b = list[i + dir];
    if (!a || !b || a.age !== b.age) return;
    const ia = events.indexOf(a), ib = events.indexOf(b);
    events[ia] = b; events[ib] = a;
    setDirty(true); render();
    const again = $("rows").querySelector(`[data-move="${id}:${dir}"]`);
    if (again && !again.disabled) again.focus();
    else { const other = $("rows").querySelector(`[data-move="${id}:${-dir}"]`); if (other) other.focus(); }
  }

  function render() { drawChart(); drawList(); }

  function select(id) {
    selectedId = id;
    if (role === "admin") loadForm(id);
    render();
  }

  // ---------------- form ----------------
  function setEmo(v) {
    $("fEmo").value = v;
    const out = $("fEmoVal"); out.textContent = fmtEmo(+v); out.className = emoClass(+v);
  }
  $("fEmo").addEventListener("input", () => setEmo($("fEmo").value));

  function resetForm() {
    editingId = null;
    $("fAge").value = ""; $("fTitle").value = ""; $("fNote").value = ""; setEmo(0);
    $("formTitle").textContent = "Add life event"; $("fSave").textContent = "Add";
    $("fDelete").hidden = true; $("fCancel").hidden = true; showErr($("formErr"), "");
  }
  function loadForm(id) {
    const e = events.find((x) => x.id === id); if (!e) return;
    editingId = id;
    $("fAge").value = e.age; $("fTitle").value = e.title; $("fNote").value = e.note; setEmo(e.emotion);
    $("formTitle").textContent = "Edit life event"; $("fSave").textContent = "Save";
    $("fDelete").hidden = false; $("fCancel").hidden = false; showErr($("formErr"), "");
    disarmDelete();
  }
  $("addBtn").addEventListener("click", () => { selectedId = null; resetForm(); render(); $("fAge").focus(); });
  $("fCancel").addEventListener("click", () => { selectedId = null; resetForm(); render(); });

  $("form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const age = parseFloat($("fAge").value), title = $("fTitle").value.trim();
    if (!Number.isFinite(age) || age < 0 || age > 120) { showErr($("formErr"), "Enter an age between 0 and 120."); return; }
    if (!title) { showErr($("formErr"), "Write the event."); return; }
    const data = { age, title: title.slice(0, 80), emotion: +$("fEmo").value, note: $("fNote").value };
    if (editingId) {
      const cur = events.find((x) => x.id === editingId);
      // Moved to a different age: put it last among that age's events, like a newly added one.
      if (cur.age !== age) { events = events.filter((x) => x !== cur); events.push(cur); }
      Object.assign(cur, data);
      const keep = editingId;
      resetForm(); selectedId = keep; loadForm(keep);
    } else {
      // A new event: highlight it, but leave the form ready for the next one,
      // keeping the age so several events from the same year are quick to add.
      const e = { id: newId(), ...data }; events.push(e); selectedId = e.id;
      resetForm(); $("fAge").value = age; $("fTitle").focus();
    }
    setDirty(true);
    render();
  });

  let delTimer = null;
  function disarmDelete() { clearTimeout(delTimer); $("fDelete").classList.remove("armed"); $("fDelete").textContent = "Delete"; }
  $("fDelete").addEventListener("click", () => {
    const b = $("fDelete");
    if (!b.classList.contains("armed")) { b.classList.add("armed"); b.textContent = "Confirm delete"; delTimer = setTimeout(disarmDelete, 3000); return; }
    disarmDelete();
    events = events.filter((x) => x.id !== editingId);
    selectedId = null; resetForm(); setDirty(true); render();
  });

  // ---------------- save / import / passwords ----------------
  $("saveBtn").addEventListener("click", async () => {
    if (gh) { clearTimeout(syncTimer); syncNow(); return; }
    const json = await buildFileJson();
    file = json;
    download("data.json", JSON.stringify(json, null, 1));
    setDirty(false);
    notice("Saved data.json. Upload it to your repository to update the site.", 7000);
  });

  $("importBtn").addEventListener("click", () => $("importFile").click());
  $("importFile").addEventListener("change", async () => {
    const f = $("importFile").files[0]; $("importFile").value = ""; if (!f) return;
    try {
      const j = JSON.parse(await f.text());
      if (!j || !Array.isArray(j.events)) throw 0;
      const incoming = normalize(j.events);
      let added = 0, updated = 0;
      for (const e of incoming) {
        const i = events.findIndex((x) => x.id === e.id);
        if (i >= 0) { events[i] = e; updated++; } else { events.push(e); added++; }
      }
      setDirty(true); render();
      notice(`Imported: ${added} added, ${updated} updated. Press “Save file” to keep them.`, 8000);
    } catch { notice("This file can't be imported. Use an export from My Life Line.", 6000); }
  });

  $("pwBtn").addEventListener("click", () => { $("pwForm").hidden = !$("pwForm").hidden; if (!$("pwForm").hidden) $("pwAdmin").focus(); });
  $("pwCancel").addEventListener("click", () => { $("pwForm").hidden = true; $("pwAdmin").value = ""; $("pwViewer").value = ""; showErr($("pwErr"), ""); });
  $("pwForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const a = $("pwAdmin").value, v = $("pwViewer").value;
    if (!a && !v) { showErr($("pwErr"), "Enter at least one new password."); return; }
    if ((a && a.length < 2) || (v && v.length < 2)) { showErr($("pwErr"), "Use at least 2 characters."); return; }
    const users = { ...file.users };
    if (a) users.admin = await wrapFor(a, dataKeyRaw);
    if (v) users.viewer = await wrapFor(v, dataKeyRaw);
    file = { ...file, users };
    if (a) { await setDeviceKey(a); if (gh) await storeToken(); }
    $("pwAdmin").value = ""; $("pwViewer").value = ""; showErr($("pwErr"), ""); $("pwForm").hidden = true;
    setDirty(true);
    notice(gh ? "Passwords changed." : "Passwords changed. Press “Save file” and upload data.json, or the old passwords keep working.", 9000);
  });

  // ---------------- GitHub autosave ----------------
  // The token never goes into the repository. It is kept only in this browser's storage,
  // encrypted with a key derived from the admin password, and lives in memory only while logged in.
  const GH_STORE = "lifeline.github.v1", SALT_STORE = "lifeline.devsalt.v1";
  let gh = null;            // { owner, repo, branch, token, sha }
  let deviceKey = null;     // derived from admin password; encrypts the stored token
  let syncTimer = null, syncing = false, syncAgain = false;

  const lsGet = (k) => { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } };
  const lsSet = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch { return false; } };
  const lsDel = (k) => { try { localStorage.removeItem(k); } catch {} };
  const NAME_RE = /^[A-Za-z0-9._-]{1,100}$/;

  async function setDeviceKey(pass) {
    let salt = lsGet(SALT_STORE);
    if (typeof salt !== "string") { salt = b64(rand(16)); lsSet(SALT_STORE, salt); }
    deviceKey = await passwordKey(pass, unb64(salt), ITERATIONS);
  }
  async function storeToken() {
    const iv = rand(12);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, deviceKey, te.encode(gh.token));
    return lsSet(GH_STORE, { owner: gh.owner, repo: gh.repo, branch: gh.branch, iv: b64(iv), ct: b64(ct) });
  }

  async function initGitHub(pass) {
    await setDeviceKey(pass);
    const saved = lsGet(GH_STORE);
    if (!saved) { updateSyncUi(); return; }
    try {
      const token = td.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(saved.iv) }, deviceKey, unb64(saved.ct)));
      gh = { owner: saved.owner, repo: saved.repo, branch: saved.branch || "main", token, sha: null };
    } catch { gh = null; updateSyncUi(); status("Reconnect GitHub", "bad"); return; }
    updateSyncUi();
    try { await pullLatest(); status("Saved", "ok"); if (dirty) scheduleSync(); }
    catch (e) { status(e.message === "auth" ? "GitHub token expired" : "GitHub offline", "bad"); }
  }

  function apiUrl(path) { return `https://api.github.com/repos/${encodeURIComponent(gh.owner)}/${encodeURIComponent(gh.repo)}${path}`; }
  function ghFetch(path, method = "GET", body) {
    return fetch(apiUrl(path), {
      method, cache: "no-store",
      headers: { "Authorization": `Bearer ${gh.token}`, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined
    });
  }
  const contentsPath = () => `/contents/data.json?ref=${encodeURIComponent(gh.branch)}`;

  // Load the newest data.json straight from the repository (GitHub Pages can lag a minute behind),
  // so an edit never overwrites a newer version.
  async function pullLatest() {
    const r = await ghFetch(contentsPath());
    if (r.status === 404) { gh.sha = null; return; }
    if (r.status === 401 || r.status === 403) throw new Error("auth");
    if (!r.ok) throw new Error("net");
    const j = await r.json(); gh.sha = j.sha;
    if (!j.content) return;
    const remote = JSON.parse(td.decode(unb64(j.content.replace(/\s/g, ""))));
    if (!validFile(remote)) return;
    try {
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(remote.iv) }, dataKey, unb64(remote.data));
      const d = JSON.parse(td.decode(plain));
      if (!dirty) { file = remote; events = normalize(d.events || []); selectedId = null; resetForm(); render(); }
    } catch { /* a file locked with other passwords: keep what is open */ }
  }

  function scheduleSync() { if (!gh) return; clearTimeout(syncTimer); status("Saving…"); syncTimer = setTimeout(syncNow, 1500); }

  async function syncNow() {
    if (!gh) return;
    if (syncing) { syncAgain = true; return; }
    syncing = true;
    const at = changes;
    try {
      const json = await buildFileJson();
      const content = btoa(JSON.stringify(json, null, 1));
      const put = () => ghFetch("/contents/data.json", "PUT", { message: "Update life line", content, branch: gh.branch, ...(gh.sha ? { sha: gh.sha } : {}) });
      let r = await put();
      if (r.status === 409 || r.status === 422) {
        const g = await ghFetch(contentsPath());
        gh.sha = g.ok ? (await g.json()).sha : null;
        r = await put();
      }
      if (r.status === 401 || r.status === 403 || r.status === 404) throw new Error("auth");
      if (!r.ok) throw new Error("net");
      gh.sha = (await r.json()).content.sha;
      file = json;
      if (changes === at) setDirty(false);
      status("Saved", "ok");
    } catch (e) {
      if (e.message === "auth") status("Not saved: check GitHub token", "bad");
      else { status("Not saved, retrying…", "bad"); syncTimer = setTimeout(syncNow, 10000); }
    } finally {
      syncing = false;
      if (syncAgain) { syncAgain = false; scheduleSync(); }
    }
  }

  function status(text, kind = "") {
    const s = $("syncStatus"); s.textContent = text; s.className = "status admin-only toggle " + kind; s.hidden = role !== "admin";
  }
  function updateSyncUi() {
    if (role !== "admin") return;
    $("saveBtn").hidden = !!gh;
    $("ghForget").hidden = !lsGet(GH_STORE);
    if (!gh) $("syncStatus").hidden = true;
  }

  $("ghBtn").addEventListener("click", () => {
    const f = $("ghForm"); f.hidden = !f.hidden; if (f.hidden) return;
    const saved = lsGet(GH_STORE);
    let owner = gh?.owner || saved?.owner || "", repo = gh?.repo || saved?.repo || "";
    if (!owner && location.hostname.endsWith(".github.io")) {
      owner = location.hostname.split(".")[0];
      repo = location.pathname.split("/").filter(Boolean)[0] || location.hostname;
    }
    $("ghOwner").value = owner; $("ghRepo").value = repo; $("ghBranch").value = gh?.branch || saved?.branch || "main";
    $("ghToken").value = ""; showErr($("ghErr"), "");
    (owner ? $("ghToken") : $("ghOwner")).focus();
  });
  $("ghCancel").addEventListener("click", () => { $("ghForm").hidden = true; $("ghToken").value = ""; });
  $("ghForget").addEventListener("click", () => {
    lsDel(GH_STORE); gh = null; clearTimeout(syncTimer);
    $("ghForm").hidden = true; $("ghToken").value = "";
    updateSyncUi(); setDirty(dirty);
    notice("GitHub disconnected on this browser. Revoke the token on GitHub if you no longer need it.", 8000);
  });
  $("ghForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const owner = $("ghOwner").value.trim(), repo = $("ghRepo").value.trim(), branch = $("ghBranch").value.trim() || "main", token = $("ghToken").value.trim();
    const err = $("ghErr");
    if (!NAME_RE.test(owner) || !NAME_RE.test(repo)) { showErr(err, "Check the account and repository names."); return; }
    if (!/^[A-Za-z0-9_./-]{1,200}$/.test(branch)) { showErr(err, "Check the branch name."); return; }
    if (!token) { showErr(err, "Paste your token."); return; }
    showErr(err, ""); $("ghConnect").disabled = true;
    const prev = gh;
    gh = { owner, repo, branch, token, sha: null };
    try {
      const r = await ghFetch("");
      if (r.status === 401) throw new Error("This token doesn't work. Create a new one.");
      if (r.status === 404 || r.status === 403) throw new Error("No access to this repository. Check the name and the token's repository access.");
      if (!r.ok) throw new Error("GitHub didn't answer. Try again.");
      const info = await r.json();
      if (info.permissions && !info.permissions.push) throw new Error("The token can't write. Give it “Contents: Read and write”.");
      const g = await ghFetch(contentsPath());
      gh.sha = g.ok ? (await g.json()).sha : null;
      const stored = await storeToken();
      $("ghToken").value = ""; $("ghForm").hidden = true;
      updateSyncUi();
      changes++; dirty = true; await syncNow();
      notice(stored ? "Autosave is on. Every change is saved to GitHub." : "Autosave is on until you log out. This browser can't remember the token.", 7000);
    } catch (e) {
      gh = prev; showErr(err, e.message || "Couldn't connect.");
    } finally { $("ghConnect").disabled = false; }
  });

  boot();
})();
