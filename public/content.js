// content.js
// Gmail content script for PhishGuard. Expects tokenizer.js, model.js, and
// classifier.js to be loaded before this file by the extension manifest.

(() => {
  if (window.__PHISHGUARD_CONTENT_LOADED__) return;
  window.__PHISHGUARD_CONTENT_LOADED__ = true;

  const MODEL_THRESHOLD = 0.5;
  const SCAN_DEBOUNCE_MS = 450;
  const URL_SHORTENERS = new Set([
    "bit.ly",
    "bitly.com",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
    "trib.al",
    "x.co",
  ]);

  const DANGEROUS_ATTACHMENT_EXTENSIONS = new Set([
    "ade",
    "adp",
    "apk",
    "app",
    "bat",
    "cmd",
    "com",
    "cpl",
    "dmg",
    "exe",
    "hta",
    "iso",
    "jar",
    "js",
    "jse",
    "lnk",
    "msi",
    "ps1",
    "scr",
    "vbe",
    "vbs",
    "wsf",
  ]);

  const URGENCY_PATTERNS = [
    /\burgent\b/i,
    /\bimmediate(?:ly)?\b/i,
    /\bact now\b/i,
    /\bverify now\b/i,
    /\bfinal notice\b/i,
    /\baccount (?:has been )?(?:limited|locked|suspended|disabled)\b/i,
    /\b(?:within|in the next)\s+\d{1,2}\s+(?:hours?|days?)\b/i,
    /\bexpires? (?:today|soon|immediately)\b/i,
    /\bunauthorized (?:login|transaction|activity)\b/i,
    /\bpayment failed\b/i,
    /\bconfirm your identity\b/i,
  ];

  const BRAND_DOMAINS = [
    { brand: "amazon", domains: ["amazon.com"] },
    { brand: "apple", domains: ["apple.com", "icloud.com"] },
    { brand: "bank of america", domains: ["bankofamerica.com"] },
    { brand: "chase", domains: ["chase.com", "jpmchase.com"] },
    { brand: "docusign", domains: ["docusign.com"] },
    { brand: "dropbox", domains: ["dropbox.com"] },
    { brand: "facebook", domains: ["facebook.com", "meta.com"] },
    { brand: "google", domains: ["google.com", "gmail.com"] },
    { brand: "instagram", domains: ["instagram.com", "meta.com"] },
    { brand: "microsoft", domains: ["microsoft.com", "office.com", "outlook.com", "live.com"] },
    { brand: "netflix", domains: ["netflix.com"] },
    { brand: "paypal", domains: ["paypal.com"] },
    { brand: "wells fargo", domains: ["wellsfargo.com"] },
  ];

  const SUSPICIOUS_BRAND_SPELLINGS = [
    /paypa[1l-]/i,
    /g00gle|go0gle|goog1e/i,
    /micr0soft|rnicrosoft/i,
    /amaz0n|arnazon/i,
    /netf[l1i]ix/i,
    /app[1l]e/i,
  ];

  let latestResult = createIdleResult("Open an email in Gmail to scan it.");
  let lastFingerprint = "";
  let scanTimer = null;

  function isVisible(element) {
    if (!element) return false;
    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);
    return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
  }

  function getText(element) {
    return (element?.innerText || element?.textContent || "").replace(/\s+/g, " ").trim();
  }

  function normalizeUrl(rawUrl) {
    const trimmed = String(rawUrl || "").trim().replace(/[),.;\]]+$/g, "");
    if (!trimmed || /^(mailto|tel|javascript):/i.test(trimmed)) return null;

    try {
      return new URL(trimmed.startsWith("www.") ? `https://${trimmed}` : trimmed);
    } catch {
      return null;
    }
  }

  function extractUrls(root, emailText) {
    const urls = new Map();
    const addUrl = (rawUrl) => {
      const parsed = normalizeUrl(rawUrl);
      if (parsed) urls.set(parsed.href, parsed);
    };

    root.querySelectorAll("a[href]").forEach((anchor) => addUrl(anchor.href));

    const textUrlMatches = emailText.match(/\b(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [];
    textUrlMatches.forEach(addUrl);

    return Array.from(urls.values());
  }

  function getSenderFromMessage(messageRoot) {
    const senderNode =
      messageRoot.querySelector("span[email]") ||
      messageRoot.querySelector("[data-hovercard-id*='@']") ||
      document.querySelector("span[email]");

    const senderEmail =
      senderNode?.getAttribute("email") ||
      senderNode?.getAttribute("data-hovercard-id") ||
      "";

    const senderName = getText(senderNode) || senderEmail;

    return {
      name: senderName,
      email: senderEmail,
      domain: senderEmail.includes("@") ? senderEmail.split("@").pop().toLowerCase() : "",
    };
  }

  function getSubject() {
    return getText(document.querySelector("h2.hP")) || document.title.replace(/\s+-\s+Gmail$/i, "").trim();
  }

  function getOpenMessageRoot() {
    const candidates = Array.from(document.querySelectorAll("div[role='listitem'], div.adn.ads"))
      .filter((node) => isVisible(node) && node.querySelector(".a3s, [data-message-id]"));

    return candidates.at(-1) || document.querySelector("div[role='main']");
  }

  function extractAttachmentNames(messageRoot) {
    const names = new Set();

    messageRoot.querySelectorAll("[download_url]").forEach((node) => {
      const downloadUrl = node.getAttribute("download_url") || "";
      const parts = downloadUrl.split(":");
      const filename = parts.length > 1 ? parts[1] : "";
      if (filename) names.add(filename.trim());
    });

    messageRoot.querySelectorAll("[aria-label*='attachment' i], [aria-label*='download' i]").forEach((node) => {
      const label = node.getAttribute("aria-label") || "";
      const text = getText(node);
      const candidate = text || label;
      if (candidate) names.add(candidate.trim());
    });

    return Array.from(names);
  }

  function extractEmail() {
    const messageRoot = getOpenMessageRoot();
    if (!messageRoot) return null;

    const bodyNodes = Array.from(messageRoot.querySelectorAll(".a3s, div[dir='ltr']"))
      .filter(isVisible)
      .map(getText)
      .filter(Boolean);

    const body = bodyNodes.length ? bodyNodes.join("\n\n") : getText(messageRoot);
    const subject = getSubject();
    const sender = getSenderFromMessage(messageRoot);
    const emailText = [`Subject: ${subject}`, `From: ${sender.name} <${sender.email}>`, body].join("\n\n");

    if (!body || emailText.length < 20) return null;

    return {
      subject,
      sender,
      body,
      text: emailText,
      urls: extractUrls(messageRoot, emailText),
      attachments: extractAttachmentNames(messageRoot),
    };
  }

  function getHostLabel(url) {
    return url.hostname.replace(/^www\./i, "");
  }

  function hasIpAddress(url) {
    const host = url.hostname.replace(/^\[|\]$/g, "");
    return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || /^[a-f0-9:]{3,}$/i.test(host) && host.includes(":");
  }

  function getAttachmentExtension(filename) {
    const cleanName = filename.toLowerCase().split("?")[0].trim();
    const match = cleanName.match(/\.([a-z0-9]+)$/i);
    return match ? match[1] : "";
  }

  function looksLikeFakeSender(sender) {
    const senderText = `${sender.name || ""} ${sender.email || ""}`.toLowerCase();
    const domain = sender.domain || "";

    for (const { brand, domains } of BRAND_DOMAINS) {
      const brandAppears = senderText.includes(brand);
      const domainMatches = domains.some((trustedDomain) => domain === trustedDomain || domain.endsWith(`.${trustedDomain}`));
      if (brandAppears && domain && !domainMatches) {
        return {
          matched: true,
          detail: `${sender.name || sender.email} appears to reference ${brand}, but the sender domain is ${domain}.`,
        };
      }
    }

    const suspiciousSpelling = SUSPICIOUS_BRAND_SPELLINGS.find((pattern) => pattern.test(senderText));
    if (suspiciousSpelling) {
      return {
        matched: true,
        detail: `${sender.email || sender.name} contains a suspicious brand-like spelling.`,
      };
    }

    return { matched: false, detail: "Sender did not match the spoofing checks." };
  }

  function runHeuristicChecks(email) {
    const signals = [];
    let score = 0;

    const addSignal = (title, detail, level, weight) => {
      signals.push({ title, detail, level });
      score += weight;
    };

    const fakeSender = looksLikeFakeSender(email.sender);
    if (fakeSender.matched) {
      addSignal("Suspicious sender", fakeSender.detail, "HIGH", 25);
    }

    const httpUrls = email.urls.filter((url) => url.protocol === "http:");
    if (httpUrls.length) {
      addSignal("Unencrypted link", `${getHostLabel(httpUrls[0])} uses HTTP instead of HTTPS.`, "MEDIUM", 15);
    }

    const ipUrls = email.urls.filter(hasIpAddress);
    if (ipUrls.length) {
      addSignal("IP address link", `${ipUrls[0].hostname} is used directly in a link.`, "HIGH", 20);
    }

    const shortenedUrls = email.urls.filter((url) => URL_SHORTENERS.has(getHostLabel(url)));
    if (shortenedUrls.length) {
      addSignal("URL shortener", `${getHostLabel(shortenedUrls[0])} can hide the final destination.`, "MEDIUM", 15);
    }

    const urgencyMatch = URGENCY_PATTERNS.find((pattern) => pattern.test(email.text));
    if (urgencyMatch) {
      addSignal("Urgency language", "The message pressures the reader to act quickly.", "MEDIUM", 10);
    }

    const dangerousAttachment = email.attachments.find((name) => DANGEROUS_ATTACHMENT_EXTENSIONS.has(getAttachmentExtension(name)));
    if (dangerousAttachment) {
      addSignal("Dangerous attachment", `${dangerousAttachment} uses a risky file type.`, "HIGH", 25);
    }

    if (!signals.length) {
      signals.push({
        title: "Heuristic checks",
        detail: "No spoofed sender, risky URLs, urgent wording, IP links, shorteners, or dangerous attachments found.",
        level: "LOW",
      });
    }

    return {
      score: Math.min(score, 100),
      signals,
    };
  }

  function runModel(emailText) {
    if (typeof classifyText !== "function" || typeof PHISHING_MODEL === "undefined") {
      return {
        probability: 0,
        isPhishing: false,
        unavailable: true,
      };
    }

    return classifyText(emailText, PHISHING_MODEL, MODEL_THRESHOLD);
  }

  function combineResults(email, modelResult, heuristicResult) {
    const mlScore = Math.round((modelResult.probability || 0) * 100);
    const score = Math.min(100, Math.round(mlScore * 0.50 + heuristicResult.score * 0.50));
    const status = modelResult.isPhishing || heuristicResult.score >= 40 || score >= 55 ? "phishing" : "safe";

    return {
      source: "gmail",
      status,
      verdict: status === "phishing" ? "Phishing risk detected" : "Email looks safe",
      score,
      analyzedAt: new Date().toISOString(),
      email: {
        senderName: email.sender.name,
        senderEmail: email.sender.email,
        senderDomain: email.sender.domain,
        subject: email.subject,
        urlCount: email.urls.length,
        attachmentCount: email.attachments.length,
      },
      model: {
        probability: Number((modelResult.probability || 0).toFixed(4)),
        isPhishing: Boolean(modelResult.isPhishing),
        threshold: MODEL_THRESHOLD,
        unavailable: Boolean(modelResult.unavailable),
      },
      heuristics: {
        score: heuristicResult.score,
        signals: heuristicResult.signals,
      },
      signals: [
        {
          title: "ML classifier",
          detail: modelResult.unavailable
            ? "Classifier files were not available on this page."
            : `Model phishing probability: ${mlScore}/100.`,
          level: modelResult.isPhishing ? "HIGH" : "LOW",
        },
        ...heuristicResult.signals,
      ],
    };
  }

  function createIdleResult(message) {
    return {
      source: "gmail",
      status: "idle",
      verdict: message,
      score: 0,
      analyzedAt: new Date().toISOString(),
      email: null,
      model: null,
      heuristics: { score: 0, signals: [] },
      signals: [],
    };
  }

  function publishResult(result) {
    latestResult = result;
    window.dispatchEvent(new CustomEvent("phishguard:result", { detail: result }));

    if (typeof chrome !== "undefined" && chrome.runtime?.id) {
      try {
        const pendingMessage = chrome.runtime.sendMessage({ type: "PHISHGUARD_RESULT_UPDATED", result });
        if (pendingMessage?.catch) {
          pendingMessage.catch(() => {
            // The popup may be closed; the latest result remains available by request.
          });
        }
      } catch {
        // The popup may be closed; the latest result remains available by request.
      }
    }
  }

  function analyzeCurrentEmail() {
    const email = extractEmail();
    if (!email) {
      publishResult(createIdleResult("No open Gmail message detected."));
      return;
    }

    const fingerprint = [email.sender.email, email.subject, email.body.slice(0, 300)].join("|");
    if (fingerprint === lastFingerprint) return;
    lastFingerprint = fingerprint;

    const modelResult = runModel(email.text);
    const heuristicResult = runHeuristicChecks(email);
    publishResult(combineResults(email, modelResult, heuristicResult));
  }

  function scheduleScan() {
    window.clearTimeout(scanTimer);
    scanTimer = window.setTimeout(analyzeCurrentEmail, SCAN_DEBOUNCE_MS);
  }

  if (typeof chrome !== "undefined" && chrome.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (message?.type === "PHISHGUARD_SCAN_EMAIL") {
        lastFingerprint = "";
        analyzeCurrentEmail();
        sendResponse({ ok: true, result: latestResult });
        return true;
      }

      if (message?.type === "PHISHGUARD_GET_RESULT") {
        sendResponse({ ok: true, result: latestResult });
        return true;
      }

      return false;
    });
  }

  const observer = new MutationObserver(scheduleScan);
  observer.observe(document.body, { childList: true, subtree: true });
  window.addEventListener("hashchange", () => {
    lastFingerprint = "";
    scheduleScan();
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) scheduleScan();
  });

  scheduleScan();
})();
