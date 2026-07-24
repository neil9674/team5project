import { ScanResult, ThreatSignal } from './types';

export interface EmailLink {
  href: string;
  text: string;
}

export interface EmailData {
  sender: string;
  subject: string;
  body: string;
  source?: string;
  links?: EmailLink[];
}

const knownBrands = [
  { name: 'PayPal', domains: ['paypal.com'], patterns: [/paypal/i] },
  { name: 'Google', domains: ['google.com', 'accounts.google.com'], patterns: [/google/i, /gmail/i] },
  { name: 'Microsoft', domains: ['microsoft.com', 'outlook.com', 'office.com', 'live.com'], patterns: [/microsoft/i, /outlook/i, /office 365/i, /hotmail/i] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com'], patterns: [/apple/i, /icloud/i] },
];

const urgencyPatterns = [
  /urgent/i,
  /immediate action/i,
  /verify your account/i,
  /update your information/i,
  /account.*(limited|locked|suspended|disabled)/i,
  /(act now|as soon as possible|without delay)/i,
];

const phishingPhrases = [
  /verify your account/i,
  /confirm your identity/i,
  /suspend.*account/i,
  /unauthorized activity/i,
  /security alert/i,
  /update payment/i,
  /billing information/i,
  /(click|tap) (here|below)/i,
  /login to your account/i,
];

const suspiciousDomainPatterns = [/paypa[l1]/i, /goog1e/i, /micros0ft/i, /m1crosoft/i, /account.*login/i];
const linkShortenerPatterns = [/^https?:\/\/(?:bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|t\.co)/i];

function normalizeText(value: string) {
  return value.replace(/\s+/g, ' ').trim();
}

function extractDomain(value: string) {
  const emailMatch = value.match(/@([\w.-]+)/);
  if (emailMatch) {
    return emailMatch[1].toLowerCase();
  }
  const urlMatch = value.match(/https?:\/\/([^\/?#\s]+)/i);
  if (urlMatch) {
    return urlMatch[1].toLowerCase();
  }
  return value.toLowerCase();
}

function isBrandDomain(domain: string) {
  return knownBrands.some((brand) => brand.domains.some((allowed) => domain.endsWith(allowed)));
}

function findBrandByText(text: string) {
  return knownBrands.find((brand) => brand.patterns.some((pattern) => pattern.test(text)));
}

function isSuspiciousUrl(href: string) {
  if (/^mailto:/i.test(href)) {
    return false;
  }
  if (/^javascript:/i.test(href)) {
    return true;
  }
  const domain = extractDomain(href);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
    return true;
  }
  if (/xn--/.test(domain)) {
    return true;
  }
  if (suspiciousDomainPatterns.some((pattern) => pattern.test(domain))) {
    return true;
  }
  return false;
}

export function analyzeEmail(email: EmailData): ScanResult {
  const text = normalizeText(`${email.sender}\n${email.subject}\n${email.body}`);
  const signals: ThreatSignal[] = [];
  const senderDomain = extractDomain(email.sender);
  const brandMention = findBrandByText(text);
  const senderBrandSafe = isBrandDomain(senderDomain);

  if (!email.sender || senderDomain === 'unknown sender') {
    signals.push({ title: 'Sender address missing', detail: 'Unable to determine sender domain.', level: 'MEDIUM' });
  }

  if (brandMention && !senderBrandSafe) {
    signals.push({
      title: 'Brand impersonation detected',
      detail: `${brandMention.name} is mentioned but the sender domain is ${senderDomain}.`,
      level: 'HIGH',
    });
  }

  if (suspiciousDomainPatterns.some((pattern) => pattern.test(senderDomain))) {
    signals.push({ title: 'Suspicious sender domain', detail: `${senderDomain} looks like a homoglyph or typo-squatted domain.`, level: 'HIGH' });
  }

  const urgency = urgencyPatterns.some((pattern) => pattern.test(text));
  const phishingText = phishingPhrases.some((pattern) => pattern.test(text));
  if (urgency) {
    signals.push({ title: 'Urgency or pressure language', detail: 'The email uses urgent phrasing to force action.', level: 'MEDIUM' });
  }
  if (phishingText) {
    signals.push({ title: 'Phishing phrase detected', detail: 'Common phishing language is present in the email.', level: 'MEDIUM' });
  }

  const allLinks = email.links && email.links.length ? email.links : Array.from(text.matchAll(/https?:\/\/[\w\-\.\/%?=&#]+/gi)).map((m) => ({ href: m[0], text: m[0] }));

  allLinks.forEach((link) => {
    const hrefDomain = extractDomain(link.href);
    if (isSuspiciousUrl(link.href)) {
      signals.push({ title: 'Suspicious URL detected', detail: link.href, level: 'HIGH' });
    }
    if (brandMention && !hrefDomain.includes(brandMention.domains[0])) {
      signals.push({ title: 'Link destination mismatch', detail: `Email mentions ${brandMention.name} but the destination is ${hrefDomain}.`, level: 'HIGH' });
    }
    if (link.text && link.text !== link.href && link.text.toLowerCase().includes(brandMention?.name.toLowerCase() || 'paypal') && !/paypal\.com/i.test(link.href)) {
      signals.push({ title: 'Link text mismatch', detail: `Link text references a trusted brand but destination is ${hrefDomain}.`, level: 'HIGH' });
    }
    if (linkShortenerPatterns.some((pattern) => pattern.test(link.href))) {
      signals.push({ title: 'URL shortener detected', detail: link.href, level: 'MEDIUM' });
    }
    if (/(login|verify|update|secure|account|bank|confirm)/i.test(link.text) && !/(paypal\.com|google\.com|microsoft\.com|apple\.com|accounts\.google\.com)/i.test(link.href)) {
      signals.push({ title: 'Credential harvesting pattern', detail: `Link text suggests login or verification but destination is ${hrefDomain}.`, level: 'HIGH' });
    }
  });

  if (allLinks.length === 0 && /(click here|visit the link|login below)/i.test(text)) {
    signals.push({ title: 'No link present', detail: 'The email asks for clicks but no link could be parsed.', level: 'MEDIUM' });
  }

  if (!email.body || email.body.length < 20) {
    signals.push({ title: 'Empty or truncated body', detail: 'The email body appears empty or too short to verify.', level: 'MEDIUM' });
  }

  const score = Math.min(
    100,
    10 +
      signals.reduce((sum, signal) => {
        if (signal.level === 'HIGH') return sum + 30;
        if (signal.level === 'MEDIUM') return sum + 15;
        return sum + 5;
      }, 0),
  );
  const status: ScanResult['status'] = score >= 60 ? 'phishing' : 'safe';

  return {
    status,
    score,
    signals: signals.length
      ? signals
      : [{ title: 'No suspicious signals found', detail: 'This email appears legitimate.', level: 'LOW' }],
  };
}
