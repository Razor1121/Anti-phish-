// Standalone simulation of checkPhishing logic with minimal helpers

const { URL } = require('url');

// minimal string similarity (normalized Levenshtein, but simpler: ratio of matches)
function compareTwoStrings(a, b) {
  if (a === b) return 1;
  const len = Math.max(a.length, b.length);
  let same = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] === b[i]) same++;
  }
  return same / len;
}

const stringSimilarity = { compareTwoStrings };

// import real helpers from the module so simulation stays aligned
const heuristics = require('./modules/moderation/phishingHeuristics');
const tld = {
  getDomain: heuristics.getDomain,
  getSubdomain: heuristics.getSubdomain,
  getTld: heuristics.getTld
};

const punycode = {
  toASCII: (str) => str // no IDN handling
};

// stub axios head to just return object with same URL
const axios = {
  head: async (url, opts) => ({ request: { res: { responseUrl: url } } })
};

const dns = {
  resolve: async (host) => ['1.2.3.4']
};

async function loadModel() {
  return {
    predict: (features) => {
      const sum = features.reduce((a, b) => a + b, 0);
      return 1 / (1 + Math.exp(-sum / features.length));
    }
  };
}

// copy of checkPhishing but with above helpers
async function checkPhishing(input) {
  let url = input.url || input.message;
  let isMessage = !!input.message;
  let riskScore = 0;
  let reasons = [];
  let features = [];

  if (isMessage) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const matches = url.match(urlRegex);
    if (matches) url = matches[0];
    else return { isPhishing: false, riskScore: 0, reasons: ['No URL found'] };
  }
  
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return { isPhishing: true, riskScore: 100, reasons: ['Invalid URL format'] };
  }

  const hostname = parsed.hostname;
  const domain = tld.getDomain(hostname);
  const subdomain = tld.getSubdomain(hostname);
  const path = parsed.pathname;
  const query = parsed.search;

  const legitDomains = [
    'paypal.com', 'google.com', 'bankofamerica.com', 'apple.com', 'amazon.com',
    'microsoft.com', 'facebook.com', 'twitter.com', 'instagram.com', 'netflix.com',
    'chase.com', 'wellsfargo.com', 'citibank.com', 'usbank.com', 'capitalone.com'
  ];

  const phishingKeywords = [
    'login', 'secure', 'account', 'verify', 'update', 'banking', 'password',
    'signin', 'auth', 'recovery', 'billing', 'payment', 'support', 'helpdesk'
  ];
  const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'site', 'online'];

  // heuristics
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) || /^[\da-f:]+$/i.test(hostname)) {
    riskScore += 30;
    reasons.push('URL uses IP address (potential obfuscation)');
    features.push(1);
  }

  if (shorteners.includes(domain)) {
    riskScore += 20;
    reasons.push('URL shortener detected (often hides phishing)');
    features.push(1);
  }

  legitDomains.forEach(legit => {
    const similarity = stringSimilarity.compareTwoStrings(domain, legit);
    if (similarity > 0.7 && domain !== legit) {
      riskScore += 40;
      reasons.push(`Domain similar to ${legit} (typosquatting score: ${similarity})`);
      features.push(similarity);
    }
  });

  const punyHostname = punycode.toASCII(hostname);
  if (punyHostname !== hostname) {
    riskScore += 35;
    reasons.push('Internationalized Domain Name (IDN) detected - potential homograph attack');
    features.push(1);
    legitDomains.forEach(legit => {
      const sim = stringSimilarity.compareTwoStrings(punyHostname.replace('xn--', ''), legit);
      if (sim > 0.8) {
        riskScore += 20;
        reasons.push(`Punycode similar to ${legit}`);
      }
    });
  }

  const parsedTld = tld.getTld(hostname);
  if (subdomain.split('.').length > 2 || suspiciousTLDs.includes(parsedTld)) {
    riskScore += 15;
    reasons.push('Suspicious TLD or deep subdomain (common in free domain phishing)');
    features.push(1);
  }

  phishingKeywords.forEach(kw => {
    if (path.toLowerCase().includes(kw) || query.toLowerCase().includes(kw)) {
      riskScore += 10;
      reasons.push(`Phishing keyword '${kw}' in URL path/query`);
      features.push(1);
    }
  });

  if (url.length > 100) {
    riskScore += 10;
    reasons.push('Excessively long URL (potential obfuscation)');
    features.push(url.length / 100);
  }

  if (parsed.protocol !== 'https:') {
    riskScore += 25;
    reasons.push('Non-secure HTTP (phishers avoid cert costs)');
    features.push(1);
  }

  try {
    const dnsInfo = await dns.resolve(hostname);
    if (dnsInfo.length === 0) {
      riskScore += 30;
      reasons.push('No DNS resolution (possible dead or fake domain)');
    }
  } catch (err) {
    riskScore += 20;
    reasons.push('DNS resolution failed');
    features.push(1);
  }

  if (url.includes('@')) {
    riskScore += 30;
    reasons.push('URL contains @ (potential credential phishing via basic auth)');
    features.push(1);
  }

  if (/%[0-9A-Fa-f]{2}/.test(url) || /\\x[0-9A-Fa-f]{2}/.test(url)) {
    riskScore += 15;
    reasons.push('Encoded characters in URL (obfuscation technique)');
    features.push(1);
  }

  customPatterns.forEach(p => {
    try {
      const re = new RegExp(p, 'i');
      if (re.test(url) || (isMessage && re.test(input.message))) {
        riskScore += 20;
        reasons.push(`Custom pattern '${p}' matched`);
        features.push(1);
      }
    } catch (e) {}
  });
  try {
    const response = await axios.head(url, { maxRedirects: 5 });
    if (response.request.res.responseUrl !== url) {
      riskScore += 20;
      reasons.push('URL redirects (check target separately)');
    }
  } catch (err) {}

  const model = await loadModel();
  const mlProb = model.predict(features);
  riskScore += mlProb * 50;

  riskScore = Math.min(Math.max(riskScore, 0), 100);

  if (isMessage) {
    const urgencyWords = ['urgent', 'immediate', 'action required', 'suspended', 'verify now', 'click here'];
    urgencyWords.forEach(word => {
      if (input.message.toLowerCase().includes(word)) {
        riskScore += 10;
        reasons.push(`Urgency keyword '${word}' in message`);
      }
    });
  }

  return {
    isPhishing: riskScore > 50,
    riskScore,
    reasons
  };
}

// helper variables
let customPatterns = [];
const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly'];

// run some tests
(async () => {
  const testUrls = ['http://paypal.com.example.tk/login', 'http://example.com'];
  for (const u of testUrls) {
    const res = await checkPhishing({ url: u });
    console.log(`\n${u}`);
    console.log(res);
  }
})();
