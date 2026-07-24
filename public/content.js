// content.js
// Gmail content script for PhishGuard. Expects tokenizer.js, model.js, and
// classifier.js to be loaded before this file by the extension manifest.

(() => {
  if (window.__PHISHGUARD_CONTENT_LOADED__) return;
  window.__PHISHGUARD_CONTENT_LOADED__ = true;

  const MODEL_THRESHOLD = 0.72;
  const MODEL_HIGH_CONFIDENCE_THRESHOLD = 0.88;
  const PHISHING_SCORE_THRESHOLD = 75;
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

  const FREE_EMAIL_PROVIDERS = new Set([
    "aol.com",
    "gmail.com",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "mail.com",
    "outlook.com",
    "proton.me",
    "protonmail.com",
    "yahoo.com",
    "zoho.com",
  ]);

  const SUSPICIOUS_TLDS = new Set(["zip", "mov", "xyz", "top", "click", "link", "work", "country", "stream", "gq", "tk", "ml", "cf"]);

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

  const MACRO_ATTACHMENT_EXTENSIONS = new Set(["docm", "dotm", "xlsm", "xltm", "pptm", "potm", "ppsm"]);
  const ARCHIVE_EXTENSIONS = new Set(["7z", "rar", "zip"]);

  const URL_KEYWORD_PATTERNS = /(login|verify|secure|update|password|account|signin|wallet|bank|confirm|auth|reset)/i;
  const CREDENTIAL_REQUEST_PATTERNS = /(enter|confirm|verify|provide|update).{0,40}(password|passcode|credentials|login|username|account)/i;
  const PASSWORD_RESET_PATTERNS = /(password reset|reset your password|change your password|recover your account)/i;
  const ACCOUNT_VERIFICATION_PATTERNS = /(verify your account|account verification|confirm your account|validate your account)/i;
  const PAYMENT_PATTERNS = /(payment|billing|invoice|subscription|card declined|update card|bank transfer|wire transfer)/i;
  const PRIZE_PATTERNS = /(congratulations|you won|winner|claim your prize|reward|gift card|lottery|sweepstakes)/i;
  const GENERIC_GREETING_PATTERNS = /\b(dear customer|dear user|valued customer|hello customer|dear member)\b/i;
  const SECRECY_PATTERNS = /(keep this confidential|do not tell anyone|do not share this|between us|strictly confidential)/i;
  const BUSINESS_REQUEST_PATTERNS = /(wire transfer|gift cards?|change bank details|new payment instructions|urgent purchase|payroll update|direct deposit)/i;
  const FEAR_PATTERNS = /(legal action|account closure|account terminated|lose access|permanently deleted|police|lawsuit|penalty|final warning)/i;
  const POOR_GRAMMAR_PATTERNS = [
    /\bkindly\s+(?:do|send|verify|confirm|reply)\b/i,
    /\byour account will (?:be )?deactivated\b/i,
    /\bwe detected unusual\b/i,
    /\bplease to\b/i,
    /\bverify your informations\b/i,
  ];
  const KNOWN_TEMPLATE_PATTERNS = [
    /(your account has been limited|account has been temporarily locked)/i,
    /(unusual sign-in activity|unauthorized login attempt)/i,
    /(failure to verify.*account|verify.*avoid suspension)/i,
    /(invoice attached|view secure document|shared a document with you)/i,
  ];

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
  let lastPreviewFingerprint = "";
  let lastScannedFingerprint = "";
  let previewTimer = null;

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

  function getEmailDomain(emailAddress) {
    const match = String(emailAddress || "").match(/@([^>\s]+)/);
    return match ? match[1].toLowerCase().replace(/[>,]+$/g, "") : "";
  }

  function getBaseDomain(hostname) {
    const parts = String(hostname || "").toLowerCase().replace(/^www\./, "").split(".").filter(Boolean);
    return parts.length >= 2 ? parts.slice(-2).join(".") : parts.join(".");
  }

  function getTopLevelDomain(hostname) {
    const parts = String(hostname || "").toLowerCase().split(".").filter(Boolean);
    return parts.at(-1) || "";
  }

  function isHiddenElement(element) {
    if (!element) return false;
    const style = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return (
      style.display === "none" ||
      style.visibility === "hidden" ||
      Number(style.opacity) === 0 ||
      rect.width <= 1 ||
      rect.height <= 1 ||
      style.fontSize === "0px"
    );
  }

  function isExternalHost(hostname, senderDomain) {
    if (!hostname || !senderDomain) return false;
    return getBaseDomain(hostname) !== getBaseDomain(senderDomain);
  }

  function extractUrls(root, emailText) {
    const urls = new Map();
    const addUrl = (rawUrl, linkText = rawUrl, anchor = null) => {
      const parsed = normalizeUrl(rawUrl);
      if (parsed) {
        parsed.linkText = String(linkText || "").replace(/\s+/g, " ").trim();
        parsed.rawHref = String(rawUrl || "");
        parsed.isHidden = isHiddenElement(anchor);
        urls.set(parsed.href, parsed);
      }
    };

    root.querySelectorAll("a[href]").forEach((anchor) => addUrl(anchor.href, getText(anchor), anchor));

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

  function extractReplyTo(messageRoot, emailText) {
    const replyToText =
      messageRoot.querySelector("[aria-label*='reply-to' i]")?.getAttribute("aria-label") ||
      messageRoot.querySelector("[data-tooltip*='reply-to' i]")?.getAttribute("data-tooltip") ||
      "";
    const replyToMatch = `${replyToText}\n${emailText}`.match(/reply-to:\s*([^<\s]+@[^>\s]+)/i);
    const email = replyToMatch ? replyToMatch[1].trim() : "";

    return {
      email,
      domain: getEmailDomain(email),
    };
  }

  function extractAuthenticationText(messageRoot) {
    const parts = [];
    messageRoot.querySelectorAll("[aria-label], [data-tooltip], [title]").forEach((node) => {
      ["aria-label", "data-tooltip", "title"].forEach((attr) => {
        const value = node.getAttribute(attr) || "";
        if (/(spf|dkim|dmarc|mailed-by|signed-by|authenticated|authentication)/i.test(value)) {
          parts.push(value);
        }
      });
    });
    return parts.join(" ");
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
      replyTo: extractReplyTo(messageRoot, emailText),
      authenticationText: extractAuthenticationText(messageRoot),
      html: messageRoot.innerHTML || "",
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

  function findMentionedBrands(text) {
    const lowerText = String(text || "").toLowerCase();
    return BRAND_DOMAINS.filter(({ brand }) => lowerText.includes(brand));
  }

  function normalizeLookalikes(value) {
    return String(value || "")
      .toLowerCase()
      .replace(/0/g, "o")
      .replace(/1/g, "l")
      .replace(/3/g, "e")
      .replace(/5/g, "s")
      .replace(/@/g, "a")
      .replace(/rn/g, "m")
      .replace(/[^a-z]/g, "");
  }

  function levenshteinDistance(left, right) {
    const a = normalizeLookalikes(left);
    const b = normalizeLookalikes(right);
    const matrix = Array.from({ length: a.length + 1 }, (_, row) => [row]);

    for (let col = 1; col <= b.length; col += 1) matrix[0][col] = col;

    for (let row = 1; row <= a.length; row += 1) {
      for (let col = 1; col <= b.length; col += 1) {
        matrix[row][col] =
          a[row - 1] === b[col - 1]
            ? matrix[row - 1][col - 1]
            : Math.min(matrix[row - 1][col - 1] + 1, matrix[row][col - 1] + 1, matrix[row - 1][col] + 1);
      }
    }

    return matrix[a.length][b.length];
  }

  function findLookalikeBrandDomain(hostname) {
    const baseName = getBaseDomain(hostname).split(".")[0];

    for (const { brand, domains } of BRAND_DOMAINS) {
      const trustedNames = domains.map((domain) => domain.split(".")[0]);
      const isTrusted = domains.some((domain) => getBaseDomain(hostname) === getBaseDomain(domain));
      if (isTrusted) continue;

      if (trustedNames.some((trustedName) => levenshteinDistance(baseName, trustedName) <= 1 || normalizeLookalikes(baseName).includes(normalizeLookalikes(trustedName)))) {
        return brand;
      }
    }

    return "";
  }

  function hasExcessiveCapitalization(text) {
    const letters = String(text || "").replace(/[^a-z]/gi, "");
    if (letters.length < 25) return false;
    const uppercase = letters.replace(/[^A-Z]/g, "").length;
    return uppercase / letters.length > 0.45;
  }

  function hasExcessivePunctuation(text) {
    return /[!?]{3,}/.test(text) || (String(text || "").match(/!/g) || []).length >= 5;
  }

  function getUrlParamCount(url) {
    return Array.from(url.searchParams.keys()).length;
  }

  function hasRedirectParameter(url) {
    return Array.from(url.searchParams.entries()).some(([key, value]) => {
      return /(redirect|redir|url|next|target|dest|destination|continue|return)/i.test(key) && /^https?:\/\//i.test(value);
    });
  }

  function getVisibleUrlFromText(linkText) {
    const match = String(linkText || "").match(/\b(?:https?:\/\/|www\.)[^\s<>"']+/i);
    return match ? normalizeUrl(match[0]) : null;
  }

  function getKnownBrandForText(text) {
    return BRAND_DOMAINS.find(({ brand }) => String(text || "").toLowerCase().includes(brand));
  }

  function getAttachmentRisk(filename, emailText) {
    const lowerName = String(filename || "").toLowerCase();
    const extension = getAttachmentExtension(lowerName);
    const doubleExtension = /\.[a-z0-9]{2,5}\.(exe|scr|js|vbs|bat|cmd|com|ps1|jar|iso|lnk)$/i.test(lowerName);
    const suspiciousName = /(invoice|payment|receipt|refund|secure|password|scan|voicemail|document|urgent)/i.test(lowerName);
    const passwordProtected = ARCHIVE_EXTENSIONS.has(extension) && /(password|passcode|protected|encrypted)/i.test(`${lowerName} ${emailText}`);

    if (doubleExtension) return { title: "Double file extension", detail: `${filename} hides a risky extension.`, level: "HIGH", weight: 25 };
    if (DANGEROUS_ATTACHMENT_EXTENSIONS.has(extension)) return { title: "Dangerous attachment", detail: `${filename} uses a risky file type.`, level: "HIGH", weight: 25 };
    if (MACRO_ATTACHMENT_EXTENSIONS.has(extension)) return { title: "Macro-enabled document", detail: `${filename} can run embedded macros.`, level: "HIGH", weight: 20 };
    if (passwordProtected) return { title: "Password-protected archive", detail: `${filename} appears to require a password.`, level: "MEDIUM", weight: 15 };
    if (suspiciousName) return { title: "Suspicious attachment name", detail: `${filename} uses a common phishing lure name.`, level: "MEDIUM", weight: 10 };

    return null;
  }

  function hasNewDomainIndicators(hostname) {
    const baseName = getBaseDomain(hostname).split(".")[0] || "";
    const digitCount = (baseName.match(/\d/g) || []).length;
    const hyphenCount = (baseName.match(/-/g) || []).length;
    const vowelCount = (baseName.match(/[aeiou]/g) || []).length;

    return (
      (baseName.length >= 16 && vowelCount <= 3) ||
      digitCount >= 4 ||
      hyphenCount >= 3 ||
      /(?:secure|verify|account|login|update|support|service).{0,10}\d{2,}/i.test(baseName)
    );
  }

  function runHeuristicChecks(email) {
    const signals = [];
    const signalKeys = new Set();
    let score = 0;
    const senderDomain = email.sender.domain || "";
    const senderBaseDomain = getBaseDomain(senderDomain);
    const mentionedBrands = findMentionedBrands(email.text);
    const primaryMentionedBrand = mentionedBrands[0];

    const addSignal = (title, detail, level, weight) => {
      const key = `${title}:${detail}`;
      if (signalKeys.has(key)) return;
      signalKeys.add(key);
      signals.push({ title, detail, level });
      score += weight;
    };

    const fakeSender = looksLikeFakeSender(email.sender);
    if (fakeSender.matched) {
      addSignal("Suspicious sender", fakeSender.detail, "HIGH", 25);
    }

    if (email.replyTo?.domain && senderDomain && getBaseDomain(email.replyTo.domain) !== senderBaseDomain) {
      addSignal("Reply-To address mismatch", `Replies go to ${email.replyTo.domain}, not ${senderDomain}.`, "HIGH", 25);
    }

    if (
      primaryMentionedBrand &&
      FREE_EMAIL_PROVIDERS.has(senderDomain) &&
      !primaryMentionedBrand.domains.some((domain) => senderBaseDomain === getBaseDomain(domain))
    ) {
      addSignal("Free email provider impersonation", `${primaryMentionedBrand.brand} is mentioned from a free email domain (${senderDomain}).`, "HIGH", 25);
    }

    const senderLookalikeBrand = senderDomain ? findLookalikeBrandDomain(senderDomain) : "";
    if (senderLookalikeBrand) {
      addSignal("Lookalike domain detection", `${senderDomain} resembles ${senderLookalikeBrand}.`, "HIGH", 25);
    }

    if (SUSPICIOUS_BRAND_SPELLINGS.some((pattern) => pattern.test(senderDomain))) {
      addSignal("Suspicious domain spelling", `${senderDomain} contains brand-like spelling variations.`, "HIGH", 20);
    }

    if (senderDomain && senderDomain.split(".").length > 4) {
      addSignal("Excessive subdomains", `${senderDomain} has unusually many domain levels.`, "MEDIUM", 10);
    }

    const senderTld = getTopLevelDomain(senderDomain);
    if (SUSPICIOUS_TLDS.has(senderTld)) {
      addSignal("Suspicious top-level domain", `Sender uses .${senderTld}, which is common in abuse campaigns.`, "MEDIUM", 10);
    }

    if (senderDomain && hasNewDomainIndicators(senderDomain)) {
      addSignal("New-domain style indicators", `${senderDomain} has naming patterns often seen in newly registered throwaway domains.`, "MEDIUM", 10);
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

    email.urls.forEach((url) => {
      const host = getHostLabel(url);
      const baseHost = getBaseDomain(host);
      const urlTld = getTopLevelDomain(host);
      const visibleUrl = getVisibleUrlFromText(url.linkText);
      const linkedBrand = getKnownBrandForText(url.linkText || "");
      const lookalikeBrand = findLookalikeBrandDomain(host);

      if (isExternalHost(host, senderDomain) && URL_KEYWORD_PATTERNS.test(`${url.pathname} ${url.search} ${url.linkText || ""}`)) {
        addSignal("Sender domain mismatch", `Action link points to ${baseHost}, not ${senderBaseDomain || "the sender domain"}.`, "HIGH", 20);
      }

      if (lookalikeBrand) {
        addSignal("Lookalike domain detection", `${host} resembles ${lookalikeBrand}.`, "HIGH", 25);
      }

      if (SUSPICIOUS_BRAND_SPELLINGS.some((pattern) => pattern.test(host))) {
        addSignal("Suspicious domain spelling", `${host} contains brand-like spelling variations.`, "HIGH", 20);
      }

      if (host.split(".").length > 4) {
        addSignal("Excessive subdomains", `${host} has unusually many domain levels.`, "MEDIUM", 10);
      }

      if (SUSPICIOUS_TLDS.has(urlTld)) {
        addSignal("Suspicious top-level domain", `${host} uses .${urlTld}.`, "MEDIUM", 10);
      }

      if (hasNewDomainIndicators(host)) {
        addSignal("New-domain style indicators", `${host} has naming patterns often seen in newly registered throwaway domains.`, "MEDIUM", 10);
      }

      if (url.href.length > 180) {
        addSignal("Extremely long URL", `${host} uses a very long link.`, "MEDIUM", 10);
      }

      if (getUrlParamCount(url) > 8) {
        addSignal("Excessive URL parameters", `${host} includes many tracking or routing parameters.`, "MEDIUM", 10);
      }

      if (/%[0-9a-f]{2}/i.test(url.href) || /xn--/i.test(host)) {
        addSignal("Encoded URL", `${host} contains encoded or punycode text.`, "MEDIUM", 10);
      }

      if (URL_KEYWORD_PATTERNS.test(`${url.pathname} ${url.search}`)) {
        addSignal("Suspicious URL keywords", `${host} uses account, login, verify, or password language.`, "MEDIUM", 10);
      }

      if (visibleUrl && getBaseDomain(visibleUrl.hostname) !== baseHost) {
        addSignal("Link text and URL mismatch", `Visible text shows ${getHostLabel(visibleUrl)}, but the link goes to ${host}.`, "HIGH", 25);
      }

      if (linkedBrand && !linkedBrand.domains.some((domain) => baseHost === getBaseDomain(domain))) {
        addSignal("Link text and URL mismatch", `Link text references ${linkedBrand.brand}, but the destination is ${host}.`, "HIGH", 25);
      }

      if (hasRedirectParameter(url) || /redirect|redir|outbound|click/i.test(url.pathname)) {
        addSignal("Possible redirect link", `${host} appears to route through a redirect.`, "MEDIUM", 10);
      }

      if (URL_KEYWORD_PATTERNS.test(`${url.pathname} ${url.search} ${url.linkText || ""}`) && isExternalHost(host, senderDomain)) {
        addSignal("External login page", `Login or verification link points outside the sender domain to ${host}.`, "HIGH", 20);
      }

      if (url.isHidden) {
        addSignal("Hidden link", `${host} is hidden or nearly invisible in the email HTML.`, "HIGH", 20);
      }
    });

    const urgencyMatch = URGENCY_PATTERNS.find((pattern) => pattern.test(email.text));
    if (urgencyMatch) {
      addSignal("Urgency language", "The message pressures the reader to act quickly.", "MEDIUM", 10);
    }

    if (FEAR_PATTERNS.test(email.text)) addSignal("Fear or threat language", "The message threatens consequences to pressure action.", "MEDIUM", 10);
    if (CREDENTIAL_REQUEST_PATTERNS.test(email.text)) addSignal("Credential request", "The message asks for login credentials or account secrets.", "HIGH", 20);
    if (PASSWORD_RESET_PATTERNS.test(email.text)) addSignal("Password reset request", "The message asks the reader to reset or change a password.", "MEDIUM", 10);
    if (ACCOUNT_VERIFICATION_PATTERNS.test(email.text)) addSignal("Account verification request", "The message asks the reader to verify an account.", "MEDIUM", 10);
    if (PAYMENT_PATTERNS.test(email.text)) addSignal("Payment or billing request", "The message discusses payment, billing, invoices, or bank details.", "MEDIUM", 10);
    if (PRIZE_PATTERNS.test(email.text)) addSignal("Prize or reward language", "The message uses prize, reward, or winner language.", "MEDIUM", 10);
    if (GENERIC_GREETING_PATTERNS.test(email.text)) addSignal("Generic greeting", "The message uses a non-personal greeting.", "LOW", 5);
    if (hasExcessiveCapitalization(email.text)) addSignal("Excessive capitalization", "The message uses an unusual amount of uppercase text.", "LOW", 5);
    if (hasExcessivePunctuation(email.text)) addSignal("Excessive punctuation", "The message uses repeated urgent punctuation.", "LOW", 5);
    if (POOR_GRAMMAR_PATTERNS.some((pattern) => pattern.test(email.text))) addSignal("Poor grammar pattern", "The message contains wording often seen in phishing templates.", "LOW", 5);
    if (SECRECY_PATTERNS.test(email.text)) addSignal("Request for secrecy", "The message asks the reader not to share the request.", "MEDIUM", 15);
    if (BUSINESS_REQUEST_PATTERNS.test(email.text)) addSignal("Unusual business request", "The message asks for a risky business or money-handling action.", "HIGH", 20);
    if (KNOWN_TEMPLATE_PATTERNS.some((pattern) => pattern.test(email.text))) addSignal("Known phishing template language", "The message resembles a common phishing template.", "HIGH", 20);

    if (/<form|<input|type=["']?password/i.test(email.html)) {
      addSignal("Suspicious HTML elements", "The message contains forms, inputs, or password-style HTML.", "HIGH", 20);
    }

    if (/spf|dkim|dmarc|authentication/i.test(email.authenticationText) && /(fail|softfail|neutral|unauthenticated|not authenticated)/i.test(email.authenticationText)) {
      addSignal("Email authentication issue", "Gmail authentication details suggest SPF, DKIM, or DMARC did not pass.", "HIGH", 25);
    }

    email.attachments.forEach((name) => {
      const risk = getAttachmentRisk(name, email.text);
      if (risk) addSignal(risk.title, risk.detail, risk.level, risk.weight);
    });

    if (mentionedBrands.length) {
      const trustedBrandDomainFound = mentionedBrands.some(({ domains }) => {
        return email.urls.some((url) => domains.some((domain) => getBaseDomain(url.hostname) === getBaseDomain(domain))) ||
          domains.some((domain) => senderBaseDomain === getBaseDomain(domain));
      });

      if (!trustedBrandDomainFound) {
        addSignal("Brand impersonation scoring", `Mentions ${mentionedBrands.map(({ brand }) => brand).join(", ")} without a matching trusted sender or link domain.`, "HIGH", 20);
      }
    }

    const senderReputationScore =
      (FREE_EMAIL_PROVIDERS.has(senderDomain) ? 10 : 0) +
      (senderLookalikeBrand ? 25 : 0) +
      (SUSPICIOUS_TLDS.has(senderTld) ? 10 : 0) +
      (hasNewDomainIndicators(senderDomain) ? 10 : 0);
    if (senderReputationScore >= 25) {
      addSignal("Email sender reputation scoring", `${senderDomain || "Sender"} has multiple local reputation warning signs.`, "HIGH", 20);
    }

    if (signals.filter((signal) => signal.level === "HIGH" || signal.level === "MEDIUM").length >= 3) {
      addSignal("Multiple phishing indicators", "Several independent phishing indicators were found together.", "HIGH", 20);
    }

    if (!signals.length) {
      signals.push({
        title: "Heuristic checks",
        detail: "No local sender, URL, language, HTML, or attachment indicators were found.",
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
    const hasRiskyHeuristics = heuristicResult.signals.some((signal) => signal.level === "HIGH" || signal.level === "MEDIUM");
    const weightedModelScore = hasRiskyHeuristics ? mlScore * 0.5 : mlScore * 0.35;
    const weightedHeuristicScore = hasRiskyHeuristics ? heuristicResult.score * 0.5 : heuristicResult.score * 0.45;
    const score = Math.min(100, Math.max(mlScore, heuristicResult.score, Math.round(weightedModelScore + weightedHeuristicScore)));
    const modelHighConfidence = (modelResult.probability || 0) >= MODEL_HIGH_CONFIDENCE_THRESHOLD;
    const modelSignalLevel = modelHighConfidence ? "HIGH" : mlScore >= 50 ? "MEDIUM" : "LOW";
    const status =
      modelHighConfidence ||
      heuristicResult.score >= 55 ||
      (score >= PHISHING_SCORE_THRESHOLD && (hasRiskyHeuristics || modelResult.isPhishing))
        ? "phishing"
        : "safe";

    return {
      source: "gmail",
      status,
      verdict: status === "phishing"
        ? "Phishing risk detected"
        : score >= 50
          ? "Model sees moderate risk. Review before clicking links."
          : "Email looks safe",
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
        isPhishing: status === "phishing",
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
          level: modelSignalLevel,
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

  function createPreviewResult(email, message = "Ready to scan this email.") {
    return {
      source: "gmail",
      status: "idle",
      verdict: message,
      score: 0,
      analyzedAt: new Date().toISOString(),
      email: {
        senderName: email.sender.name,
        senderEmail: email.sender.email,
        senderDomain: email.sender.domain,
        subject: email.subject,
        urlCount: email.urls.length,
        attachmentCount: email.attachments.length,
      },
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

  function publishPreview(result) {
    latestResult = result;

    if (typeof chrome !== "undefined" && chrome.runtime?.id) {
      try {
        const pendingMessage = chrome.runtime.sendMessage({ type: "PHISHGUARD_EMAIL_PREVIEW_UPDATED", result });
        if (pendingMessage?.catch) pendingMessage.catch(() => {});
      } catch {
        // The popup may be closed; the latest preview remains available by request.
      }
    }
  }

  function getCurrentEmailPreview() {
    const email = extractEmail();
    return email ? createPreviewResult(email) : createIdleResult("No open Gmail message detected.");
  }

  function updateCurrentEmailPreview() {
    const previewResult = getCurrentEmailPreview();
    const fingerprint = [
      previewResult.email?.senderEmail || previewResult.email?.senderName || "",
      previewResult.email?.subject || "",
    ].join("|");

    if (fingerprint === lastPreviewFingerprint) return;
    lastPreviewFingerprint = fingerprint;
    publishPreview(previewResult);
  }

  function analyzeCurrentEmail() {
    const email = extractEmail();
    if (!email) {
      publishResult(createIdleResult("No open Gmail message detected."));
      return;
    }

    const fingerprint = [email.sender.email, email.subject, email.body.slice(0, 300)].join("|");
    if (fingerprint === lastScannedFingerprint) return;
    lastScannedFingerprint = fingerprint;

    const modelResult = runModel(email.text);
    const heuristicResult = runHeuristicChecks(email);
    publishResult(combineResults(email, modelResult, heuristicResult));
  }

  function schedulePreview() {
    window.clearTimeout(previewTimer);
    previewTimer = window.setTimeout(updateCurrentEmailPreview, SCAN_DEBOUNCE_MS);
  }

  if (typeof chrome !== "undefined" && chrome.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (message?.type === "PHISHGUARD_SCAN_EMAIL") {
        lastScannedFingerprint = "";
        analyzeCurrentEmail();
        sendResponse({ ok: true, result: latestResult });
        return true;
      }

      if (message?.type === "PHISHGUARD_GET_PREVIEW") {
        const result = getCurrentEmailPreview();
        latestResult = result;
        lastPreviewFingerprint = [
          result.email?.senderEmail || result.email?.senderName || "",
          result.email?.subject || "",
        ].join("|");
        sendResponse({ ok: true, result });
        return true;
      }

      if (message?.type === "PHISHGUARD_GET_RESULT") {
        sendResponse({ ok: true, result: latestResult });
        return true;
      }

      return false;
    });
  }

  const observer = new MutationObserver(schedulePreview);
  observer.observe(document.body, { childList: true, subtree: true });
  window.addEventListener("hashchange", () => {
    lastPreviewFingerprint = "";
    lastScannedFingerprint = "";
    schedulePreview();
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) schedulePreview();
  });

  schedulePreview();
})();
