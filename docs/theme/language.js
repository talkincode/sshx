(function () {
  const pagePairs = {
    "index.html": "zh/index.html",
    "getting-started.html": "zh/getting-started.html",
    "host-management.html": "zh/host-management.html",
    "sftp.html": "zh/sftp.html",
    "agent-scripting.html": "zh/agent-scripting.html",
    "usage-scenarios.html": "zh/usage-scenarios.html",
    "security-guidelines.html": "zh/security-guidelines.html",
    "troubleshooting.html": "zh/troubleshooting.html",
  };

  const reversePairs = Object.fromEntries(
    Object.entries(pagePairs).map(([english, chinese]) => [chinese, english]),
  );

  function stripBookPrefix(pathname) {
    let path = decodeURI(pathname).replace(/\/+/g, "/");
    const endedWithSlash = path.endsWith("/");
    if (endedWithSlash) {
      path += "index.html";
    }

    const parts = path.split("/").filter(Boolean);
    if (parts.length === 0) {
      return "index.html";
    }

    const zhIndex = parts.indexOf("zh");
    if (zhIndex >= 0) {
      const zhParts = parts.slice(zhIndex + 1);
      if (zhParts.length === 0) {
        return "zh/index.html";
      }
      const last = zhParts[zhParts.length - 1];
      if (last === "index.html" && zhParts.length > 1) {
        return `zh/${zhParts.slice(0, -1).join("/")}.html`;
      }
      if (last.endsWith(".html")) {
        return `zh/${zhParts.join("/")}`;
      }
      return `zh/${zhParts.join("/")}.html`;
    }

    const last = parts[parts.length - 1];
    const previous = parts[parts.length - 2];
    if (last === "index.html" && previous && pagePairs[`${previous}.html`]) {
      return `${previous}.html`;
    }
    if (last.endsWith(".html")) {
      return last;
    }
    if (pagePairs[`${last}.html`]) {
      return `${last}.html`;
    }
    return "index.html";
  }

  function currentPage() {
    return stripBookPrefix(window.location.pathname);
  }

  function currentLanguage() {
    return currentPage().startsWith("zh/") ? "zh" : "en";
  }

  function counterpartFor(page) {
    return page.startsWith("zh/")
      ? reversePairs[page] || "index.html"
      : pagePairs[page] || "zh/index.html";
  }

  function relativeTarget(targetPage) {
    const page = currentPage();
    if (page.startsWith("zh/") && !targetPage.startsWith("zh/")) {
      return "../" + targetPage;
    }
    if (!page.startsWith("zh/") && targetPage.startsWith("zh/")) {
      return targetPage;
    }
    if (page.startsWith("zh/") && targetPage.startsWith("zh/")) {
      return targetPage.replace(/^zh\//, "");
    }
    return targetPage;
  }

  function classifyHref(href) {
    if (!href) {
      return "en";
    }
    try {
      const url = new URL(href, window.location.href);
      return stripBookPrefix(url.pathname).startsWith("zh/") ? "zh" : "en";
    } catch (_) {
      return href.includes("/zh/") || href.startsWith("zh/") ? "zh" : "en";
    }
  }

  function addLanguageSwitcher() {
    const menuBar =
      document.getElementById("menu-bar") ||
      document.getElementById("mdbook-menu-bar");
    if (!menuBar || document.querySelector(".language-switcher")) {
      return;
    }

    const lang = currentLanguage();
    const page = currentPage();
    const target = counterpartFor(page);
    const switcher = document.createElement("nav");
    switcher.className = "language-switcher";
    switcher.setAttribute("aria-label", "Language");

    const en = document.createElement("a");
    en.href = lang === "en" ? "#" : relativeTarget(target);
    en.textContent = "EN";
    en.title = "Read in English";
    en.setAttribute("aria-label", "Read in English");
    if (lang === "en") {
      en.className = "active";
      en.setAttribute("aria-current", "page");
    }

    const zh = document.createElement("a");
    zh.href = lang === "zh" ? "#" : relativeTarget(target);
    zh.textContent = "中";
    zh.title = "阅读中文";
    zh.setAttribute("aria-label", "阅读中文");
    if (lang === "zh") {
      zh.className = "active";
      zh.setAttribute("aria-current", "page");
    }

    switcher.append(en, zh);
    const targetContainer = menuBar.querySelector(".right-buttons") || menuBar;
    targetContainer.prepend(switcher);
  }

  function filterSidebar() {
    const sidebar =
      document.getElementById("sidebar") ||
      document.getElementById("mdbook-sidebar");
    if (!sidebar) {
      return;
    }
    const lang = currentLanguage();
    sidebar.querySelectorAll("li.chapter-item").forEach((item) => {
      const anchor = item.querySelector(
        ":scope > .chapter-link-wrapper > a, :scope > a",
      );
      if (!anchor) {
        return;
      }
      const linkLanguage = classifyHref(anchor.getAttribute("href"));
      item.dataset.languageHidden = linkLanguage === lang ? "false" : "true";
    });
  }

  function run() {
    addLanguageSwitcher();
    filterSidebar();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run);
  } else {
    run();
  }
})();
