// Central configuration for phishing detection heuristics

module.exports = {
  // list of well-known domains to compare against for typosquatting
  legitDomains: [
    'paypal.com', 'google.com', 'bankofamerica.com', 'apple.com', 'amazon.com',
    'microsoft.com', 'facebook.com', 'twitter.com', 'instagram.com', 'netflix.com',
    'chase.com', 'wellsfargo.com', 'citibank.com', 'usbank.com', 'capitalone.com'
  ],

  phishingKeywords: [
    'login', 'secure', 'account', 'verify', 'update', 'banking', 'password',
    'signin', 'auth', 'recovery', 'billing', 'payment', 'support', 'helpdesk'
  ],

  suspiciousTLDs: ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'site', 'online'],

  urlShorteners: ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly'],

  // scoring thresholds / weights - can be tuned externally
  thresholds: {
    phishingScore: 50    // score above which we consider a link phishing
  },

  weights: {
    ipAddress: 30,
    shortener: 20,
    typosquatting: 40,
    idnHomograph: 35,
    idnSimilarity: 20,
    suspiciousTld: 15,
    keyword: 10,
    longUrl: 10,
    nonHttps: 25,
    dnsFailure: 20,
    atSymbol: 30,
    encodedChars: 15,
    redirect: 20,
    googleSafeBrowsing: 50,
    virusTotal: 30,
    phishTank: 60
  }
};
