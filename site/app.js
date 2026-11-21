/* Coldpin Documentation Portal Interactive Module
 * Pure ES2020 | Zero innerHTML | Strict CSP ('self') | WCAG 2.2 AA
 */
(function () {
  "use strict";

  var MAX_INPUT_LEN = 4096;
  var announcer = document.getElementById("live-announcer");

  function announce(msg) {
    if (!announcer) return;
    announcer.textContent = "";
    window.setTimeout(function () {
      announcer.textContent = msg;
    }, 30);
  }

  /* ========================================================================
     1. THEME TOGGLE (Light / Dark, prefers-color-scheme fallback)
     ======================================================================== */
  var root = document.documentElement;
  var themeBtn = document.getElementById("theme-toggle");

  function resolveTheme() {
    var attr = root.getAttribute("data-theme");
    if (attr === "light" || attr === "dark") return attr;
    var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    return prefersDark ? "dark" : "light";
  }

  function syncThemeButton() {
    if (!themeBtn) return;
    var current = resolveTheme();
    themeBtn.textContent = current === "dark" ? "Light" : "Dark";
    themeBtn.setAttribute("aria-label", current === "dark" ? "Switch to light theme" : "Switch to dark theme");
  }

  try {
    var savedTheme = window.localStorage.getItem("coldpin-docs-theme");
    if (savedTheme === "light" || savedTheme === "dark") {
      root.setAttribute("data-theme", savedTheme);
    }
  } catch (_) {}
  syncThemeButton();

  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var next = resolveTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try {
        window.localStorage.setItem("coldpin-docs-theme", next);
      } catch (_) {}
      syncThemeButton();
      announce("Switched to " + next + " theme");
    });
  }

  /* ========================================================================
     2. MOBILE SIDEBAR DRAWER
     ======================================================================== */
  var sidebar = document.getElementById("docs-sidebar");
  var menuBtn = document.getElementById("mobile-menu-btn");

  function setMenuOpen(open) {
    if (!sidebar || !menuBtn) return;
    sidebar.classList.toggle("is-open", open);
    menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
    menuBtn.textContent = open ? "Close" : "Menu";
  }

  if (menuBtn && sidebar) {
    menuBtn.addEventListener("click", function () {
      setMenuOpen(!sidebar.classList.contains("is-open"));
    });
    sidebar.addEventListener("click", function (ev) {
      if (ev.target && ev.target.closest && ev.target.closest("a.nav-link")) {
        setMenuOpen(false);
      }
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && sidebar.classList.contains("is-open")) {
        setMenuOpen(false);
        menuBtn.focus();
      }
    });
  }

  /* ========================================================================
     3. ACCESSIBLE WAI-ARIA TAB GROUPS (Install + Interactive Lab)
     ======================================================================== */
  var tablists = document.querySelectorAll('[role="tablist"]');

  function activateTab(tablist, targetTab, shouldFocus) {
    var tabs = tablist.querySelectorAll('[role="tab"]');
    for (var i = 0; i < tabs.length; i++) {
      var tab = tabs[i];
      var selected = tab === targetTab;
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.setAttribute("tabindex", selected ? "0" : "-1");
      var panelId = tab.getAttribute("aria-controls");
      var panel = panelId ? document.getElementById(panelId) : null;
      if (panel) {
        panel.hidden = !selected;
      }
    }
    if (shouldFocus) {
      targetTab.focus();
    }
  }

  for (var t = 0; t < tablists.length; t++) {
    (function (tablist) {
      var tabs = Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]'));
      tabs.forEach(function (tab, idx) {
        tab.addEventListener("click", function () {
          activateTab(tablist, tab, false);
        });
        tab.addEventListener("keydown", function (ev) {
          var nextIdx = -1;
          if (ev.key === "ArrowRight") nextIdx = (idx + 1) % tabs.length;
          else if (ev.key === "ArrowLeft") nextIdx = (idx - 1 + tabs.length) % tabs.length;
          else if (ev.key === "Home") nextIdx = 0;
          else if (ev.key === "End") nextIdx = tabs.length - 1;
          if (nextIdx !== -1) {
            ev.preventDefault();
            activateTab(tablist, tabs[nextIdx], true);
          }
        });
      });
    })(tablists[t]);
  }

  /* ========================================================================
     4. COPY-TO-CLIPBOARD BUTTONS (with fallback & screen-reader live region)
     ======================================================================== */
  var copyButtons = document.querySelectorAll(".copy-btn[data-copy]");
  for (var c = 0; c < copyButtons.length; c++) {
    copyButtons[c].addEventListener("click", function (ev) {
      var btn = ev.currentTarget;
      var targetId = btn.getAttribute("data-copy");
      var el = targetId ? document.getElementById(targetId) : null;
      if (!el) return;
      var text = el.textContent || "";

      function markCopied() {
        btn.textContent = "Copied";
        announce("Copied snippet to clipboard");
        window.setTimeout(function () {
          btn.textContent = "Copy";
        }, 1600);
      }

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(markCopied, function () {
          announce("Copy failed: select the text manually");
        });
      } else {
        announce("Clipboard API unavailable: select the snippet manually");
      }
    });
  }

  /* ========================================================================
     5. INTERACTIVE PRETOOLUSE HOOK POLICY SIMULATOR (mirrors src/hook.ts)
     ======================================================================== */
  var toolSelect = document.getElementById("sim-tool");
  var payloadInput = document.getElementById("sim-payload");
  var decisionBadge = document.getElementById("sim-decision-badge");
  var metaEl = document.getElementById("sim-meta");
  var reasonEl = document.getElementById("sim-reason");
  var jsonEl = document.getElementById("sim-json");

  var SENSITIVE_FILES_RE = /(^|[\\/])(\.npmrc|\.yarnrc(\.yml)?|package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|\.coldpin\.policy\.json|\.npx-guard\.policy\.json|hooks\.json|mcp_config\.json)$/i;
  var PINNED_COLDPIN_RE = /^npx\s+--yes\s+--ignore-scripts\s+--package=(@[a-z0-9._-]+\/[a-z0-9._-]+|[a-z0-9._-]+)@[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\s+--\s+[A-Za-z0-9._/@:-]+(?:\s+[^;&|`$<>()]+)?$/;
  var POST_DASH_SHELL_RE = /\s--\s+(?:sh|bash|zsh|dash|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|node|python3?)\b/i;

  function evaluateHookSimulation(toolName, rawValue) {
    var val = String(rawValue || "").slice(0, MAX_INPUT_LEN).trim();
    if (!val) {
      return {
        hookGroup: "coldpin-npx-guard",
        decision: "force_ask",
        code: "EMPTY_OR_MALFORMED_PAYLOAD",
        reason: "Fail-closed default: empty or unparseable hook payloads request human confirmation and exit 0."
      };
    }

    if (toolName === "define_subagent") {
      if (/\b(EnableWriteTools|enable_write_tools)\s*:\s*true\b/i.test(val)) {
        return {
          hookGroup: "coldpin-delegation-guard",
          decision: "force_ask",
          code: "WRITABLE_SUBAGENT_GATE",
          reason: "Dynamic subagent requested write/command tools (EnableWriteTools: true). Requires human confirmation."
        };
      }
      return {
        hookGroup: "coldpin-delegation-guard",
        decision: "allow",
        code: "READONLY_SUBAGENT",
        reason: "Dynamic subagent omits write tools. Allowed under default host policy with exit 0."
      };
    }

    if (toolName === "write_to_file") {
      if (SENSITIVE_FILES_RE.test(val) || /(^|[\\/])(rules|agents)[\\/]/i.test(val)) {
        return {
          hookGroup: "coldpin-config-guard",
          decision: "force_ask",
          code: "SENSITIVE_CONFIG_EDIT",
          reason: "Target modifies dependency, registry, policy, agent, or hook configuration. Human confirmation required."
        };
      }
      return {
        hookGroup: "coldpin-config-guard",
        decision: "allow",
        code: "NON_SENSITIVE_FILE",
        reason: "Target path is outside protected package/registry/policy globs. Allowed immediately."
      };
    }

    if (toolName === "manage_task") {
      if (/\b(npx|pnpx|bunx|yarn\s+dlx|npm\s+(exec|ci|install|create)|curl\b.*\|\s*(sh|bash)|irm\b.*\|\s*iex)\b/i.test(val)) {
        return {
          hookGroup: "coldpin-npx-guard",
          decision: "deny",
          code: "INTERACTIVE_STDIN_INJECTION",
          reason: "Blocked runner or download-and-execute command delivered via manage_task(send_input)."
        };
      }
      return {
        hookGroup: "coldpin-npx-guard",
        decision: "allow",
        code: "BENIGN_TASK_INPUT",
        reason: "Interactive input does not invoke unvetted package runners."
      };
    }

    /* run_command evaluation */
    var unquoted = val.replace(/["'`\\]/g, "");
    if (/(\||&&|;|\$\(|`)/.test(val) && /(npx|pnpx|bunx|yarn\s+dlx|npm\s+exec|sh\b|bash\b|iex\b)/i.test(unquoted)) {
      return {
        hookGroup: "coldpin-npx-guard",
        decision: "deny",
        code: "SHELL_CHAIN_OR_PIPE_TO_EXEC",
        reason: "Blocked shell chaining, subshell, or pipe-to-shell command invoking an unvetted runner."
      };
    }
    if (/--registry=|--ignore-scripts=false/i.test(unquoted)) {
      return {
        hookGroup: "coldpin-npx-guard",
        decision: "deny",
        code: "UNSAFE_REGISTRY_OR_SCRIPT_FLAG",
        reason: "Blocked registry override or --ignore-scripts=false flag."
      };
    }
    if (PINNED_COLDPIN_RE.test(val) && !POST_DASH_SHELL_RE.test(val)) {
      return {
        hookGroup: "coldpin-npx-guard",
        decision: "force_ask",
        code: "PINNED_COLDPIN_APPROVAL",
        reason: "Exact-pinned --ignore-scripts command matches Coldpin's safe template. Never auto-approved; requests human confirmation."
      };
    }
    if (/\b(npx(\.cmd|\.exe)?|pnpx|bunx|bun\s+x|yarn\s+dlx|npm\s+(exec|ci|install|create)|deno\s+run)\b/i.test(unquoted)) {
      return {
        hookGroup: "coldpin-npx-guard",
        decision: "deny",
        code: "UNVETTED_OR_OBFUSCATED_RUNNER",
        reason: "Blocked unpinned, obfuscated, or non-canonical package runner. Inspect cold via Coldpin MCP before running."
      };
    }
    return {
      hookGroup: "coldpin-npx-guard",
      decision: "allow",
      code: "BENIGN_COMMAND",
      reason: "Command does not invoke package runners or download-and-execute chains. Passes to standard host policy."
    };
  }

  function renderHookSimulation() {
    if (!toolSelect || !payloadInput || !decisionBadge || !metaEl || !reasonEl || !jsonEl) return;
    var res = evaluateHookSimulation(toolSelect.value, payloadInput.value);
    decisionBadge.className = "decision-pill";
    if (res.decision === "allow") {
      decisionBadge.classList.add("decision-allow");
      decisionBadge.textContent = "ALLOW";
    } else if (res.decision === "force_ask") {
      decisionBadge.classList.add("decision-ask");
      decisionBadge.textContent = "FORCE_ASK";
    } else {
      decisionBadge.classList.add("decision-deny");
      decisionBadge.textContent = "DENY";
    }
    metaEl.textContent = res.hookGroup + " | " + res.code + " | exit 0";
    reasonEl.textContent = res.reason;

    var stdoutObj = res.decision === "allow"
      ? { decision: "allow" }
      : { decision: res.decision, reason: "[" + res.code + "] " + res.reason };
    jsonEl.textContent = JSON.stringify(stdoutObj, null, 2);
  }

  if (toolSelect && payloadInput) {
    toolSelect.addEventListener("change", renderHookSimulation);
    payloadInput.addEventListener("input", renderHookSimulation);
    var presetButtons = document.querySelectorAll(".preset-btn[data-sim-tool]");
    for (var p = 0; p < presetButtons.length; p++) {
      presetButtons[p].addEventListener("click", function (ev) {
        var btn = ev.currentTarget;
        toolSelect.value = btn.getAttribute("data-sim-tool") || "run_command";
        payloadInput.value = btn.getAttribute("data-sim-payload") || "";
        renderHookSimulation();
        announce("Simulated " + btn.textContent);
      });
    }
    renderHookSimulation();
  }

  /* ========================================================================
     6. INTERACTIVE 4-STATE VERDICT CARD EXPLORER
     ======================================================================== */
  var VERDICTS = {
    clean: {
      title: "semver@7.7.1",
      badgeClass: "decision-allow",
      badgeText: "VERIFIED_CLEAN_WITHIN_SCOPE (exit 0)",
      sha512: "sha512-verified (in-memory stream, 14 files, 0 lifecycle hooks)",
      parity: "Tier 1 + Tier 2 verified (Git tag matches tarball files)",
      findings: "0 malicious indicators, 0 OSV/MAL-* advisories, 0 hidden Unicode or taint chains",
      unknowns: "Runtime behavior of floating transitive dependencies is outside static tarball scope.",
      command: "npx --yes --ignore-scripts --package=semver@7.7.1 -- semver --help"
    },
    suspicious: {
      title: "fast-json-helper@2.4.1",
      badgeClass: "decision-ask",
      badgeText: "QUARANTINE_SUSPICIOUS (exit 2)",
      sha512: "sha512-verified (42 files; postinstall script present)",
      parity: "Tarball drift detected: dist/loader.js absent from Git tag v2.4.1",
      findings: "High-entropy escape density (6.12 bits/char) and dynamic Function() invocation",
      unknowns: "Obfuscated bundle requires Tier-2 REA inspection before human decision.",
      command: "# Command suppressed. Run: coldpin resolve-anchor fast-json-helper --git-dir ./repo"
    },
    malicious: {
      title: "react-cli-utils@1.9.4",
      badgeClass: "decision-deny",
      badgeText: "MALICIOUS_INDICATORS_FOUND (exit 3)",
      sha512: "sha512-verified (OSV advisory MAL-2026-00419 matched)",
      parity: "Tarball-only injection in preinstall.js; source repo HEAD uncompromised",
      findings: "TAINT_CRED_TO_NETWORK_OR_EXEC: process.env -> https.request(hxxps://collect[.]evil[.]example/ingest)",
      unknowns: "Check local package-lock.json and rotate exposed CI/developer tokens immediately.",
      command: "# Execution blocked. Run /coldpin-incident or coldpin resolve-anchor react-cli-utils"
    },
    unknown: {
      title: "native-crypto-cli@0.8.0",
      badgeClass: "decision-ask",
      badgeText: "UNVERIFIABLE_UNKNOWN (exit 2)",
      sha512: "sha512-verified (offline mode or compiled native binary)",
      parity: "Contains prebuilt ELF/PE .node binary (bin/addon.node)",
      findings: "0 JS taint findings, but native binary payload is opaque to JS/TS static analysis",
      unknowns: "Fail-closed: escalate binary to pre-registered REA server before execution.",
      command: "# Command suppressed under fail-closed policy (uninspected native artifact)"
    }
  };

  var vTitle = document.getElementById("vc-title");
  var vBadge = document.getElementById("vc-badge");
  var vSha = document.getElementById("vc-sha");
  var vParity = document.getElementById("vc-parity");
  var vFindings = document.getElementById("vc-findings");
  var vUnknowns = document.getElementById("vc-unknowns");
  var vCmd = document.getElementById("vc-cmd");

  function renderVerdictCard(key) {
    var data = VERDICTS[key] || VERDICTS.clean;
    if (!vTitle) return;
    vTitle.textContent = data.title;
    vBadge.className = "decision-pill " + data.badgeClass;
    vBadge.textContent = data.badgeText;
    vSha.textContent = data.sha512;
    vParity.textContent = data.parity;
    vFindings.textContent = data.findings;
    vUnknowns.textContent = data.unknowns;
    vCmd.textContent = data.command;
  }

  var verdictBtns = document.querySelectorAll(".preset-btn[data-verdict]");
  for (var v = 0; v < verdictBtns.length; v++) {
    verdictBtns[v].addEventListener("click", function (ev) {
      var key = ev.currentTarget.getAttribute("data-verdict");
      renderVerdictCard(key);
      announce("Showing " + key + " verdict card example");
    });
  }
  renderVerdictCard("clean");

  /* ========================================================================
     7. INSTANT KEYBOARD SEARCH DIALOG (Ctrl+K / Cmd+K / '/')
     ======================================================================== */
  var searchDialog = document.getElementById("search-dialog");
  var searchTrigger = document.getElementById("search-trigger");
  var searchInput = document.getElementById("search-input");
  var searchClose = document.getElementById("search-close");
  var searchList = document.getElementById("search-results");

  var searchIndex = [];
  var indexedSections = document.querySelectorAll("section[id][data-search]");
  for (var s = 0; s < indexedSections.length; s++) {
    var sec = indexedSections[s];
    var h = sec.querySelector("h1, h2, h3");
    searchIndex.push({
      id: sec.id,
      title: h ? h.textContent.trim() : sec.id,
      group: sec.getAttribute("data-group") || "Documentation",
      keywords: (sec.getAttribute("data-search") || "").toLowerCase()
    });
  }

  function renderSearchResults(query) {
    if (!searchList) return;
    var q = String(query || "").slice(0, 128).trim().toLowerCase();
    while (searchList.firstChild) {
      searchList.removeChild(searchList.firstChild);
    }
    var matches = searchIndex.filter(function (item) {
      if (!q) return true;
      return item.title.toLowerCase().indexOf(q) !== -1 ||
        item.group.toLowerCase().indexOf(q) !== -1 ||
        item.keywords.indexOf(q) !== -1;
    });

    if (matches.length === 0) {
      var empty = document.createElement("li");
      empty.className = "search-empty";
      empty.textContent = "No documentation sections matched that query.";
      searchList.appendChild(empty);
      return;
    }

    matches.forEach(function (item) {
      var li = document.createElement("li");
      var a = document.createElement("a");
      a.className = "search-result-link";
      a.href = "#" + item.id;
      var titleSpan = document.createElement("span");
      titleSpan.className = "search-result-title";
      titleSpan.textContent = item.title;
      var metaSpan = document.createElement("span");
      metaSpan.className = "search-result-meta";
      metaSpan.textContent = item.group;
      a.appendChild(titleSpan);
      a.appendChild(metaSpan);
      a.addEventListener("click", function () {
        if (searchDialog && searchDialog.open) searchDialog.close();
      });
      li.appendChild(a);
      searchList.appendChild(li);
    });
  }

  function openSearch() {
    if (!searchDialog || !searchDialog.showModal) return;
    renderSearchResults(searchInput ? searchInput.value : "");
    searchDialog.showModal();
    if (searchInput) {
      searchInput.focus();
      searchInput.select();
    }
  }

  if (searchTrigger) {
    searchTrigger.addEventListener("click", openSearch);
  }
  if (searchClose && searchDialog) {
    searchClose.addEventListener("click", function () {
      searchDialog.close();
    });
  }
  if (searchDialog) {
    searchDialog.addEventListener("click", function (ev) {
      if (ev.target === searchDialog) searchDialog.close();
    });
  }
  if (searchInput) {
    searchInput.addEventListener("input", function () {
      renderSearchResults(searchInput.value);
    });
  }
  document.addEventListener("keydown", function (ev) {
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") {
      ev.preventDefault();
      openSearch();
    } else if (ev.key === "/" && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      var tag = document.activeElement ? document.activeElement.tagName : "";
      if (tag !== "INPUT" && tag !== "TEXTAREA" && tag !== "SELECT") {
        ev.preventDefault();
        openSearch();
      }
    }
  });

  /* ========================================================================
     8. SCROLL-SPY (Sidebar + Right TOC via IntersectionObserver)
     ======================================================================== */
  var navLinks = Array.prototype.slice.call(document.querySelectorAll(".sidebar .nav-link[href^='#']"));
  var tocLinks = Array.prototype.slice.call(document.querySelectorAll(".toc-aside .toc-link[href^='#']"));

  function setActiveSection(id) {
    navLinks.forEach(function (link) {
      if (link.getAttribute("href") === "#" + id) {
        link.setAttribute("aria-current", "location");
      } else {
        link.removeAttribute("aria-current");
      }
    });
    tocLinks.forEach(function (link) {
      link.classList.toggle("is-active", link.getAttribute("href") === "#" + id);
    });
  }

  if ("IntersectionObserver" in window && indexedSections.length > 0) {
    var observer = new IntersectionObserver(function (entries) {
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].isIntersecting) {
          setActiveSection(entries[i].target.id);
          break;
        }
      }
    }, { rootMargin: "-15% 0px -70% 0px", threshold: 0 });

    for (var k = 0; k < indexedSections.length; k++) {
      observer.observe(indexedSections[k]);
    }
  }
})();
