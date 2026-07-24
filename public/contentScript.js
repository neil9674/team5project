function queryText(selectors) {
  for (const selector of selectors) {
    const element = document.querySelector(selector);
    if (element && element.textContent) {
      return element.textContent.trim();
    }
  }
  return '';
}

function queryAttribute(selectors, attribute) {
  for (const selector of selectors) {
    const element = document.querySelector(selector);
    if (element) {
      const attr = element.getAttribute(attribute);
      if (attr) {
        return attr.trim();
      }
    }
  }
  return '';
}

function getListText(selectors) {
  const texts = [];
  for (const selector of selectors) {
    document.querySelectorAll(selector).forEach((element) => {
      if (element.textContent) {
        texts.push(element.textContent.trim());
      }
    });
    if (texts.length) {
      break;
    }
  }
  return texts.join('\n\n');
}

function getContainer(selectors) {
  for (const selector of selectors) {
    const element = document.querySelector(selector);
    if (element) {
      return element;
    }
  }
  return document.body;
}

function getLinks(container) {
  const links = [];
  const seen = new Set();
  container.querySelectorAll('a[href]').forEach((anchor) => {
    const href = anchor.getAttribute('href')?.trim();
    if (!href || href.startsWith('mailto:')) {
      return;
    }
    const text = anchor.textContent?.trim() || href;
    const key = `${href}::${text}`;
    if (!seen.has(key)) {
      seen.add(key);
      links.push({ href, text });
    }
  });
  return links;
}

function parseGmail() {
  const sender = queryAttribute(['span.gD', 'span[email]', 'a[email]', 'span.hb'], 'email') || queryText(['span.gD', 'div[role="button"][data-tooltip]', '.h7']);
  const subject = queryText(['h2.hP', 'div[role="main"] h2', 'h2', '.hP']);
  const container = getContainer([
    'div[role="main"] div.a3s',
    'div[role="main"] .ii.gt',
    'div[role="textbox"]',
    'div.a3s.aXjCH',
  ]);
  const body = container ? container.textContent?.trim() || '' : '';
  return {
    sender: sender || 'Unknown sender',
    subject: subject || 'Unknown subject',
    body: body || 'No message body found.',
    source: 'Gmail',
    links: getLinks(container),
  };
}

function parseOutlook() {
  const sender = queryText([
    '[data-test-id="message-view-sender-name"]',
    '[data-test-id="message-view-sender-email"]',
    'div[aria-label*="From"] span',
    '[aria-label*="From"]',
  ]);
  const subject = queryText([
    '[data-test-id="message-view-subject"]',
    'div[aria-label*="Subject"]',
    'h1[role="heading"]',
    'span[aria-label*="Subject"]',
  ]);
  const container = getContainer([
    '[data-test-id="message-view-body"]',
    'div[aria-label="Message body"]',
    'div[role="document"]',
    'article[role="article"]',
    '.ReadingPane',
  ]);
  const body = container ? container.textContent?.trim() || '' : '';
  return {
    sender: sender || 'Unknown sender',
    subject: subject || 'Unknown subject',
    body: body || 'No message body found.',
    source: 'Outlook',
    links: getLinks(container),
  };
}

function parseGeneric() {
  const sender = queryText(['[data-test-id="message-view-sender-name"]', 'span[email]', 'div[aria-label*="From"]', 'span[title*="@"]']);
  const subject = queryText(['h1', 'h2', '[data-test-id="message-view-subject"]']);
  const container = getContainer(['div[role="document"]', 'article', 'div[aria-label="Message body"]']);
  const body = container ? container.textContent?.trim() || '' : '';
  return {
    sender: sender || 'Unknown sender',
    subject: subject || 'Unknown subject',
    body: body || 'No message body found.',
    source: 'unknown',
    links: getLinks(container),
  };
}

function getCurrentEmail() {
  const host = location.hostname;
  if (host.includes('mail.google.com')) {
    return parseGmail();
  }
  if (host.includes('outlook.office.com')) {
    return parseOutlook();
  }
  return parseGeneric();
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === 'GET_EMAIL_DATA') {
    sendResponse({ email: getCurrentEmail() });
  }
});
