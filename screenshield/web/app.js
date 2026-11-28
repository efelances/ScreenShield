(function () {
  "use strict";

  const state = {
    app: null,
    windows: [],
    monitors: [],
    lang: "tr",
    activeTab: "shield",
    snapshots: {
      directWindows: "",
      allowlistWindows: "",
      monitors: "",
      rules: "",
      zones: "",
      alerts: "",
    },
  };

  function t(key) {
    const dict = window.SCREENSHIELD_I18N[state.lang] || window.SCREENSHIELD_I18N.en;
    return dict[key] || window.SCREENSHIELD_I18N.en[key] || key;
  }

  function applyTranslations() {
    document.documentElement.lang = state.lang;
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      el.textContent = t(el.getAttribute("data-i18n"));
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
      el.placeholder = t(el.getAttribute("data-i18n-placeholder"));
    });
    document.querySelectorAll("[data-lang]").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-lang") === state.lang);
    });
  }

  async function api(path, options = {}) {
    const headers = Object.assign({ "X-ScreenShield-CSRF": "1" }, options.headers || {});
    if (options.body && typeof options.body !== "string") {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(options.body);
    }
    const resp = await fetch(path, Object.assign({ credentials: "same-origin", headers }, options));
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(text || `HTTP ${resp.status}`);
    }
    return resp.json();
  }

  function renderMain() {
    if (!state.app) return;
    const cfg = state.app.config;
    const m = state.app.metrics;
    const isDirect = (cfg.shield_mode || "direct_overlay") === "direct_overlay";

    state.lang = cfg.language || "tr";
    const theme = cfg.theme || "dark";
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.setAttribute("data-contrast", cfg.high_contrast ? "high" : "standard");
    applyTranslations();

    const themeBtn = document.getElementById("themeToggleBtn");
    themeBtn.textContent = theme === "dark" ? t("theme_light") : t("theme_dark");

    const pill = document.getElementById("statusBadge");
    pill.className = "status-pill";
    if (m.panic) {
      pill.classList.add("panic");
      pill.textContent = t("status_panic");
    } else if (m.sharing) {
      pill.classList.add("active");
      pill.textContent = t("status_sharing");
    } else {
      pill.textContent = t("status_standby");
    }

    const summaryEl = document.getElementById("heroSummary");
    if (m.panic) {
      summaryEl.textContent = t("summary_panic");
    } else if (!m.sharing) {
      summaryEl.textContent = t("summary_standby");
    } else if (isDirect) {
      const notifText = state.app.focus_silenced ? t("notif_muted") : t("notif_normal");
      summaryEl.textContent = t("summary_active_direct")
        .replace("{count}", String(m.active_shields || 0))
        .replace("{notif}", notifText);
    } else {
      summaryEl.textContent = t("summary_active_mirror");
    }

    const shareBtn = document.getElementById("shareToggleBtn");
    shareBtn.textContent = isDirect
      ? (m.sharing ? t("stop_shield") : t("start_shield"))
      : (m.sharing ? t("stop_share") : t("start_share"));

    document.getElementById("panicBtn").textContent = m.panic ? t("panic_release") : t("panic_activate");

    document.getElementById("styleBlurBtn").classList.toggle("active", cfg.mask_style === "blur");
    document.getElementById("styleSolidBtn").classList.toggle("active", cfg.mask_style === "solid");
    document.getElementById("focusAssistChk").checked = Boolean(cfg.auto_focus_assist);

    const overlayActive = Boolean(state.app.zone_overlays_active);
    document.getElementById("zoneOverlayToggleBtn").classList.toggle("btn-primary", overlayActive);
    document.getElementById("zonesOverlayBtn2").classList.toggle("btn-primary", overlayActive);

    document.getElementById("sendBackBtn").classList.toggle("hidden", isDirect || !m.sharing);
    document.getElementById("directWindowsCard").classList.toggle("hidden", !isDirect);
    document.getElementById("mirrorSection").classList.toggle("hidden", isDirect);
    document.getElementById("allowlistCard").classList.toggle("hidden", isDirect || cfg.mirror_mode !== "allowlist");
    document.getElementById("monitorCard").classList.toggle("hidden", isDirect || cfg.mirror_mode !== "monitor_redact");
    document.getElementById("modeAllowlistBtn").classList.toggle("active", cfg.mirror_mode === "allowlist");
    document.getElementById("modeMonitorBtn").classList.toggle("active", cfg.mirror_mode === "monitor_redact");

    // Settings controls
    document.getElementById("shieldDirectBtn").classList.toggle("active", isDirect);
    document.getElementById("shieldMirrorBtn").classList.toggle("active", !isDirect);
    document.getElementById("paddingRow").classList.toggle("hidden", !isDirect);
    document.getElementById("bufferRow").classList.toggle("hidden", isDirect);
    if (document.activeElement?.id !== "paddingRange") {
      document.getElementById("paddingRange").value = cfg.direct_padding_px ?? 4;
      document.getElementById("paddingVal").textContent = `${cfg.direct_padding_px ?? 4} px`;
    }
    if (document.activeElement?.id !== "bufferDelayRange") {
      document.getElementById("bufferDelayRange").value = cfg.buffer_delay_ms;
      document.getElementById("bufferDelayVal").textContent = `${cfg.buffer_delay_ms} ms`;
    }
    document.getElementById("contrastToggleChk").checked = Boolean(cfg.high_contrast);
    document.getElementById("hideControlChk").checked = Boolean(cfg.hide_control_from_capture);
    document.getElementById("clipboardGuardChk").checked = Boolean(cfg.clipboard_guard_enabled);
    document.getElementById("clipboardAutoClearChk").checked = Boolean(cfg.clipboard_auto_clear);
  }

  function renderDirectWindows() {
    const blockedArr = (state.app?.config?.blocked_hwnds) || [];
    const snap = JSON.stringify({
      lang: state.lang,
      blocked: blockedArr,
      windows: state.windows.map((w) => [w.hwnd, w.title, w.process_name, w.sensitive, w.shielded]),
    });
    if (snap === state.snapshots.directWindows) return;
    state.snapshots.directWindows = snap;

    const container = document.getElementById("directWindowsList");
    container.innerHTML = "";
    const blockedSet = new Set(blockedArr);
    let sensitiveCount = 0;

    state.windows.forEach((win) => {
      if (win.sensitive) sensitiveCount += 1;
      const row = document.createElement("div");
      row.className = "list-item" + (win.shielded ? " sensitive" : "");

      const main = document.createElement("div");
      main.className = "list-item-main";

      const chk = document.createElement("input");
      chk.type = "checkbox";
      chk.checked = Boolean(win.sensitive || blockedSet.has(win.hwnd));
      chk.disabled = Boolean(win.sensitive);
      chk.addEventListener("change", async () => {
        const next = new Set(state.app.config.blocked_hwnds || []);
        if (chk.checked) next.add(win.hwnd);
        else next.delete(win.hwnd);
        state.app = await api("/api/blocked-windows", {
          method: "POST",
          body: { hwnds: Array.from(next) },
        });
        await refreshWindows();
        renderAll();
      });

      const txt = document.createElement("div");
      const title = document.createElement("div");
      title.className = "item-title";
      title.textContent = win.title;
      const meta = document.createElement("div");
      meta.className = "item-meta";
      meta.textContent = win.process_name || "window";
      txt.appendChild(title);
      txt.appendChild(meta);

      main.appendChild(chk);
      main.appendChild(txt);
      row.appendChild(main);

      const actions = document.createElement("div");
      actions.className = "list-item-actions";
      if (win.sensitive) {
        const tag = document.createElement("span");
        tag.className = "tag ok";
        tag.textContent = t("rule_shielded_tag");
        actions.appendChild(tag);
      } else {
        const makeRuleBtn = document.createElement("button");
        makeRuleBtn.type = "button";
        makeRuleBtn.className = "btn btn-outline";
        makeRuleBtn.textContent = t("make_rule_btn");
        makeRuleBtn.addEventListener("click", async () => {
          const pattern = (win.process_name || win.title.slice(0, 24)).replace(/\.exe$/i, "");
          const label = win.process_name ? win.process_name.replace(/\.exe$/i, "") : win.title.slice(0, 24);
          state.app = await api("/api/rules", {
            method: "POST",
            body: { label, pattern, match_type: "contains", category: "custom", enabled: true },
          });
          await refreshWindows();
          renderAll();
        });
        actions.appendChild(makeRuleBtn);
      }
      row.appendChild(actions);
      container.appendChild(row);
    });

    document.getElementById("matchedWindowsSummary").textContent = `${sensitiveCount} ${t("sensitive_tag")}`;
  }

  function renderAllowlistWindows() {
    const allowArr = (state.app?.config?.allowlist_hwnds) || [];
    const snap = JSON.stringify({
      allow: allowArr,
      windows: state.windows.map((w) => [w.hwnd, w.title, w.sensitive]),
    });
    if (snap === state.snapshots.allowlistWindows) return;
    state.snapshots.allowlistWindows = snap;

    const container = document.getElementById("windowsList");
    container.innerHTML = "";
    const allowset = new Set(allowArr);

    state.windows.forEach((win) => {
      const row = document.createElement("div");
      row.className = "list-item" + (win.sensitive ? " sensitive" : "");

      const main = document.createElement("div");
      main.className = "list-item-main";
      const chk = document.createElement("input");
      chk.type = "checkbox";
      chk.checked = allowset.has(win.hwnd);
      chk.addEventListener("change", async () => {
        const next = new Set(state.app.config.allowlist_hwnds);
        if (chk.checked) next.add(win.hwnd);
        else next.delete(win.hwnd);
        state.app = await api("/api/allowlist", { method: "POST", body: { hwnds: Array.from(next) } });
        renderAll();
      });

      const txt = document.createElement("div");
      const title = document.createElement("div");
      title.className = "item-title";
      title.textContent = win.title;
      txt.appendChild(title);
      main.appendChild(chk);
      main.appendChild(txt);
      row.appendChild(main);
      container.appendChild(row);
    });
  }

  function renderMonitors() {
    const selectedIdx = state.app?.config?.monitor_index || 1;
    const snap = JSON.stringify({ selectedIdx, monitors: state.monitors });
    if (snap === state.snapshots.monitors) return;
    state.snapshots.monitors = snap;

    const container = document.getElementById("monitorsList");
    container.innerHTML = "";
    state.monitors.forEach((mon) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "monitor-card" + (mon.index === selectedIdx ? " active" : "");
      btn.textContent = `Display ${mon.index} (${mon.width}×${mon.height})`;
      btn.addEventListener("click", async () => {
        state.app = await api("/api/config", { method: "PUT", body: { monitor_index: mon.index } });
        renderAll();
      });
      container.appendChild(btn);
    });
  }

  function renderRules() {
    const rules = state.app?.config?.rules || [];
    const snap = JSON.stringify({ lang: state.lang, rules });
    if (snap === state.snapshots.rules) return;
    state.snapshots.rules = snap;

    const container = document.getElementById("rulesList");
    container.innerHTML = "";

    rules.forEach((rule) => {
      const row = document.createElement("div");
      row.className = "list-item";

      const main = document.createElement("div");
      main.className = "list-item-main";
      const chk = document.createElement("input");
      chk.type = "checkbox";
      chk.checked = Boolean(rule.enabled);
      chk.addEventListener("change", async () => {
        state.app = await api(`/api/rules/${encodeURIComponent(rule.id)}`, {
          method: "PUT",
          body: { enabled: chk.checked },
        });
        await refreshWindows();
        renderAll();
      });

      const txt = document.createElement("div");
      const title = document.createElement("div");
      title.className = "item-title";
      title.textContent = rule.label;
      const meta = document.createElement("div");
      meta.className = "item-meta";
      meta.textContent = `${rule.match_type} · ${rule.pattern}`;
      txt.appendChild(title);
      txt.appendChild(meta);

      main.appendChild(chk);
      main.appendChild(txt);
      row.appendChild(main);

      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "btn btn-outline";
      delBtn.textContent = t("delete_btn");
      delBtn.addEventListener("click", async () => {
        state.app = await api(`/api/rules/${encodeURIComponent(rule.id)}`, { method: "DELETE" });
        await refreshWindows();
        renderAll();
      });
      row.appendChild(delBtn);
      container.appendChild(row);
    });
  }

  function renderZones() {
    const zones = state.app?.config?.zones || [];
    const snap = JSON.stringify({ lang: state.lang, zones });
    if (snap === state.snapshots.zones) return;
    state.snapshots.zones = snap;

    const canvas = document.getElementById("zoneCanvas");
    canvas.querySelectorAll(".zone-box").forEach((n) => n.remove());
    const list = document.getElementById("zonesList");
    list.innerHTML = "";
    if (!zones.length) {
      const empty = document.createElement("div");
      empty.className = "hint-text";
      empty.textContent = t("no_zones");
      list.appendChild(empty);
      return;
    }

    zones.forEach((zone) => {
      if (zone.enabled) {
        const box = document.createElement("div");
        box.className = "zone-box";
        box.style.left = `${zone.x * 100}%`;
        box.style.top = `${zone.y * 100}%`;
        box.style.width = `${zone.width * 100}%`;
        box.style.height = `${zone.height * 100}%`;
        box.textContent = zone.label;
        canvas.appendChild(box);
      }

      const row = document.createElement("div");
      row.className = "list-item";
      const main = document.createElement("div");
      main.className = "list-item-main";
      const chk = document.createElement("input");
      chk.type = "checkbox";
      chk.checked = Boolean(zone.enabled);
      chk.addEventListener("change", async () => {
        state.app = await api(`/api/zones/${encodeURIComponent(zone.id)}`, {
          method: "PUT",
          body: { enabled: chk.checked },
        });
        renderAll();
      });

      const txt = document.createElement("div");
      const title = document.createElement("div");
      title.className = "item-title";
      title.textContent = zone.label;
      txt.appendChild(title);
      main.appendChild(chk);
      main.appendChild(txt);
      row.appendChild(main);

      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "btn btn-outline";
      delBtn.textContent = t("delete_btn");
      delBtn.addEventListener("click", async () => {
        state.app = await api(`/api/zones/${encodeURIComponent(zone.id)}`, { method: "DELETE" });
        renderAll();
      });
      row.appendChild(delBtn);
      list.appendChild(row);
    });
  }

  function renderSecurity() {
    if (!state.app) return;
    const hk = state.app.config.hotkeys;
    const status = state.app.hotkey_status || {};

    if (document.activeElement?.id !== "hkPanicInput") document.getElementById("hkPanicInput").value = hk.panic;
    if (document.activeElement?.id !== "hkShareInput") document.getElementById("hkShareInput").value = hk.share_mode;
    if (document.activeElement?.id !== "hkZonesInput") document.getElementById("hkZonesInput").value = hk.zones;

    [
      ["hkPanicStatus", status.panic],
      ["hkShareStatus", status.share_mode],
      ["hkZonesStatus", status.zones],
    ].forEach(([elId, ok]) => {
      const el = document.getElementById(elId);
      el.className = "tag " + (ok ? "ok" : "warn");
      el.textContent = ok ? t("hk_ok") : t("hk_fail");
    });

    const alerts = state.app.clipboard_alerts || [];
    const alertsSnap = JSON.stringify({ lang: state.lang, alerts });
    if (alertsSnap === state.snapshots.alerts) return;
    state.snapshots.alerts = alertsSnap;

    const alertsList = document.getElementById("clipboardAlertsList");
    alertsList.innerHTML = "";
    if (!alerts.length) {
      const empty = document.createElement("div");
      empty.className = "hint-text";
      empty.textContent = t("no_alerts");
      alertsList.appendChild(empty);
      return;
    }

    alerts.forEach((alert) => {
      const row = document.createElement("div");
      row.className = "list-item sensitive";
      const left = document.createElement("div");
      left.className = "item-title";
      left.textContent = (alert.categories || []).join(", ");
      const right = document.createElement("div");
      right.className = "item-meta";
      right.textContent = `${alert.timestamp}${alert.auto_cleared ? " · cleared" : ""}`;
      row.appendChild(left);
      row.appendChild(right);
      alertsList.appendChild(row);
    });
  }

  function renderAll() {
    renderMain();
    renderDirectWindows();
    renderAllowlistWindows();
    renderMonitors();
    renderRules();
    renderZones();
    renderSecurity();
  }

  async function refreshState() {
    state.app = await api("/api/state");
    renderAll();
  }

  async function refreshWindows() {
    const res = await api("/api/windows");
    state.windows = res.windows || [];
  }

  async function refreshMonitors() {
    const res = await api("/api/monitors");
    state.monitors = res.monitors || [];
  }

  function initZoneCanvas() {
    const canvas = document.getElementById("zoneCanvas");
    const draft = document.getElementById("zoneDraftBox");
    let startPt = null;

    canvas.addEventListener("mousedown", (ev) => {
      const rect = canvas.getBoundingClientRect();
      startPt = {
        x: Math.max(0, Math.min(1, (ev.clientX - rect.left) / rect.width)),
        y: Math.max(0, Math.min(1, (ev.clientY - rect.top) / rect.height)),
      };
      draft.classList.remove("hidden");
      draft.style.left = `${startPt.x * 100}%`;
      draft.style.top = `${startPt.y * 100}%`;
      draft.style.width = "0%";
      draft.style.height = "0%";
    });

    window.addEventListener("mousemove", (ev) => {
      if (!startPt) return;
      const rect = canvas.getBoundingClientRect();
      const curX = Math.max(0, Math.min(1, (ev.clientX - rect.left) / rect.width));
      const curY = Math.max(0, Math.min(1, (ev.clientY - rect.top) / rect.height));
      draft.style.left = `${Math.min(startPt.x, curX) * 100}%`;
      draft.style.top = `${Math.min(startPt.y, curY) * 100}%`;
      draft.style.width = `${Math.abs(curX - startPt.x) * 100}%`;
      draft.style.height = `${Math.abs(curY - startPt.y) * 100}%`;
    });

    window.addEventListener("mouseup", async (ev) => {
      if (!startPt) return;
      const rect = canvas.getBoundingClientRect();
      const curX = Math.max(0, Math.min(1, (ev.clientX - rect.left) / rect.width));
      const curY = Math.max(0, Math.min(1, (ev.clientY - rect.top) / rect.height));
      const x = Math.min(startPt.x, curX);
      const y = Math.min(startPt.y, curY);
      const width = Math.abs(curX - startPt.x);
      const height = Math.abs(curY - startPt.y);
      startPt = null;
      draft.classList.add("hidden");

      if (width < 0.03 || height < 0.03) return;
      const count = (state.app?.config?.zones?.length || 0) + 1;
      state.app = await api("/api/zones", {
        method: "POST",
        body: {
          label: `Zone ${count}`,
          x: Number(x.toFixed(4)),
          y: Number(y.toFixed(4)),
          width: Number(width.toFixed(4)),
          height: Number(height.toFixed(4)),
          style: state.app?.config?.mask_style || "blur",
          enabled: true,
        },
      });
      renderAll();
    });
  }

  function wireEvents() {
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.activeTab = btn.getAttribute("data-tab");
        document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b === btn));
        document.querySelectorAll(".tab-panel").forEach((panel) => {
          panel.classList.toggle("active", panel.id === `tab-${state.activeTab}`);
        });
      });
    });

    document.querySelectorAll("[data-lang]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        state.app = await api("/api/config", { method: "PUT", body: { language: btn.getAttribute("data-lang") } });
        renderAll();
      });
    });

    document.getElementById("themeToggleBtn").addEventListener("click", async () => {
      const next = (state.app?.config?.theme || "dark") === "dark" ? "light" : "dark";
      state.app = await api("/api/config", { method: "PUT", body: { theme: next } });
      renderAll();
    });

    document.getElementById("contrastToggleChk").addEventListener("change", async (ev) => {
      state.app = await api("/api/config", { method: "PUT", body: { high_contrast: ev.target.checked } });
      renderAll();
    });

    document.getElementById("shareToggleBtn").addEventListener("click", async () => {
      state.app = await api("/api/share/toggle", { method: "POST" });
      renderAll();
    });

    document.getElementById("sendBackBtn").addEventListener("click", async () => {
      state.app = await api("/api/mirror/send-back", { method: "POST" });
    });

    document.getElementById("panicBtn").addEventListener("click", async () => {
      state.app = await api("/api/panic/toggle", { method: "POST" });
      renderAll();
    });

    const toggleOverlays = async () => {
      state.app = await api("/api/zones/overlays/toggle", { method: "POST" });
      renderAll();
    };
    document.getElementById("zoneOverlayToggleBtn").addEventListener("click", toggleOverlays);
    document.getElementById("zonesOverlayBtn2").addEventListener("click", toggleOverlays);

    document.getElementById("shieldDirectBtn").addEventListener("click", async () => {
      state.app = await api("/api/config", { method: "PUT", body: { shield_mode: "direct_overlay" } });
      renderAll();
    });
    document.getElementById("shieldMirrorBtn").addEventListener("click", async () => {
      state.app = await api("/api/config", { method: "PUT", body: { shield_mode: "safe_mirror" } });
      renderAll();
    });

    document.getElementById("modeAllowlistBtn").addEventListener("click", async () => {
      state.app = await api("/api/config", { method: "PUT", body: { mirror_mode: "allowlist" } });
      renderAll();
    });
    document.getElementById("modeMonitorBtn").addEventListener("click", async () => {
      state.app = await api("/api/config", { method: "PUT", body: { mirror_mode: "monitor_redact" } });
      renderAll();
    });

    document.getElementById("paddingRange").addEventListener("change", async (ev) => {
      state.app = await api("/api/config", { method: "PUT", body: { direct_padding_px: Number(ev.target.value) } });
      renderAll();
    });
    document.getElementById("paddingRange").addEventListener("input", (ev) => {
      document.getElementById("paddingVal").textContent = `${ev.target.value} px`;
    });

    document.getElementById("bufferDelayRange").addEventListener("change", async (ev) => {
      state.app = await api("/api/config", { method: "PUT", body: { buffer_delay_ms: Number(ev.target.value) } });
      renderAll();
    });
    document.getElementById("bufferDelayRange").addEventListener("input", (ev) => {
      document.getElementById("bufferDelayVal").textContent = `${ev.target.value} ms`;
    });

    document.getElementById("styleBlurBtn").addEventListener("click", async () => {
      state.app = await api("/api/config", { method: "PUT", body: { mask_style: "blur" } });
      renderAll();
    });
    document.getElementById("styleSolidBtn").addEventListener("click", async () => {
      state.app = await api("/api/config", { method: "PUT", body: { mask_style: "solid" } });
      renderAll();
    });

    document.getElementById("focusAssistChk").addEventListener("change", async (ev) => {
      state.app = await api("/api/config", { method: "PUT", body: { auto_focus_assist: ev.target.checked } });
      renderAll();
    });
    document.getElementById("clipboardGuardChk").addEventListener("change", async (ev) => {
      state.app = await api("/api/config", { method: "PUT", body: { clipboard_guard_enabled: ev.target.checked } });
      renderAll();
    });
    document.getElementById("clipboardAutoClearChk").addEventListener("change", async (ev) => {
      state.app = await api("/api/config", { method: "PUT", body: { clipboard_auto_clear: ev.target.checked } });
      renderAll();
    });
    document.getElementById("hideControlChk").addEventListener("change", async (ev) => {
      state.app = await api("/api/config", { method: "PUT", body: { hide_control_from_capture: ev.target.checked } });
      renderAll();
    });

    const doRefreshWindows = async () => {
      await refreshWindows();
      renderDirectWindows();
      renderAllowlistWindows();
    };
    document.getElementById("refreshWindowsBtn").addEventListener("click", doRefreshWindows);
    document.getElementById("refreshDirectWindowsBtn").addEventListener("click", doRefreshWindows);

    document.getElementById("addRuleForm").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const label = document.getElementById("ruleLabelInput").value.trim();
      const pattern = document.getElementById("rulePatternInput").value.trim();
      const match_type = document.getElementById("ruleMatchTypeSelect").value;
      if (!label || !pattern) return;
      state.app = await api("/api/rules", {
        method: "POST",
        body: { label, pattern, match_type, category: "custom", enabled: true },
      });
      document.getElementById("ruleLabelInput").value = "";
      document.getElementById("rulePatternInput").value = "";
      await refreshWindows();
      renderAll();
    });

    const PRESETS = {
      taskbar: { label: "Taskbar", x: 0.0, y: 0.94, width: 1.0, height: 0.06 },
      bookmarks: { label: "Bookmarks", x: 0.0, y: 0.07, width: 1.0, height: 0.05 },
      notifications: { label: "Notification Corner", x: 0.74, y: 0.76, width: 0.26, height: 0.24 },
      sidebar: { label: "Left Sidebar", x: 0.0, y: 0.0, width: 0.18, height: 1.0 },
    };
    document.querySelectorAll(".preset-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const preset = PRESETS[btn.getAttribute("data-preset")];
        if (!preset) return;
        state.app = await api("/api/zones", {
          method: "POST",
          body: Object.assign({ style: state.app?.config?.mask_style || "blur", enabled: true }, preset),
        });
        renderAll();
      });
    });

    document.getElementById("hotkeysForm").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      state.app = await api("/api/config", {
        method: "PUT",
        body: {
          hotkeys: {
            panic: document.getElementById("hkPanicInput").value.trim(),
            share_mode: document.getElementById("hkShareInput").value.trim(),
            zones: document.getElementById("hkZonesInput").value.trim(),
          },
        },
      });
      renderAll();
    });

    document.getElementById("clearAlertsBtn").addEventListener("click", async () => {
      state.app = await api("/api/clipboard/alerts/clear", { method: "POST" });
      renderAll();
    });
  }

  function startPollers() {
    setInterval(async () => {
      try {
        await refreshState();
      } catch (_err) {
        // Ignore transient poll errors during shutdown.
      }
    }, 1000);

    setInterval(async () => {
      if (state.activeTab !== "shield") return;
      try {
        await refreshWindows();
        renderDirectWindows();
        renderAllowlistWindows();
      } catch (_err) {
        // Ignore transient poll errors.
      }
    }, 3000);

    setInterval(() => {
      if (!state.app) return;
      if (state.app.config.shield_mode !== "safe_mirror") return;
      const img = document.getElementById("mirrorPreviewImg");
      if (state.app.metrics.sharing || state.app.metrics.panic) {
        img.src = `/api/mirror/preview.jpg?t=${Date.now()}`;
      }
    }, 350);
  }

  async function boot() {
    applyTranslations();
    wireEvents();
    initZoneCanvas();
    await Promise.all([refreshState(), refreshWindows(), refreshMonitors()]);
    renderAll();
    startPollers();
  }

  window.addEventListener("DOMContentLoaded", boot);
})();
