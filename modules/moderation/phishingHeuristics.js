const stringSimilarity = require('string-similarity');
const tld = require('tldjs');
const punycode = require('punycode');
const { URL } = require('url');

// expose basic tld utilities so callers don't have to import tldjs directly
function getDomain(hostname) {
  return tld.getDomain ? tld.getDomain(hostname) : hostname;
}
function getSubdomain(hostname) {
  return tld.getSubdomain ? tld.getSubdomain(hostname) : '';
}
function getTld(hostname) {
  // tldjs doesn't expose a simple getter in v2; derive manually
  const parts = hostname.split('.');
  return parts.length ? parts[parts.length - 1] : '';
}

// individual heuristic helpers

function isIpAddress(hostname) {
  return (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) || /^[\da-f:]+$/i.test(hostname));
}

function domainSimilarity(domain, legitDomains, threshold = 0.7) {
  for (const legit of legitDomains) {
    const sim = stringSimilarity.compareTwoStrings(domain, legit);
    if (sim > threshold && domain !== legit) {
      return { match: legit, score: sim };
    }
  }
  return null;
}

function isIdnHomograph(hostname, legitDomains) {
  const puny = punycode.toASCII(hostname);
  if (puny !== hostname) {
    for (const legit of legitDomains) {
      const sim = stringSimilarity.compareTwoStrings(puny.replace(/^xn--/, ''), legit);
      if (sim > 0.8) {
        return { match: legit, score: sim };
      }
    }
    return { homograph: true };
  }
  return null;
}

function hasSuspiciousTldOrDeepSubdomain(hostname, suspiciousTLDs) {
  const subdomain = getSubdomain(hostname);
  const parsedTld = getTld(hostname);
  if (subdomain.split('.').length > 2 || suspiciousTLDs.includes(parsedTld)) {
    return true;
  }
  return false;
}

function containsPhishingKeyword(pathOrQuery, keywords) {
  const lower = pathOrQuery.toLowerCase();
  return keywords.filter(kw => lower.includes(kw));
}

function isUrlLong(url, length = 100) {
  return url.length > length;
}

function isNonHttps(protocol) {
  return protocol !== 'https:';
}

function containsAtSymbol(url) {
  return url.includes('@');
}

function hasEncodedChars(url) {
  return /%[0-9A-Fa-f]{2}/.test(url) || /\\x[0-9A-Fa-f]{2}/.test(url);
}

function extractFirstUrlFromMessage(message) {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const matches = message.match(urlRegex);
  return matches ? matches[0] : null;
}

module.exports = {
  isIpAddress,
  domainSimilarity,
  isIdnHomograph,
  hasSuspiciousTldOrDeepSubdomain,
  containsPhishingKeyword,
  isUrlLong,
  isNonHttps,
  containsAtSymbol,
  hasEncodedChars,
  extractFirstUrlFromMessage,

  // tld utilities
  getDomain,
  getSubdomain,
  getTld
};
