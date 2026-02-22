// phishingService.js: core logic extracted from earlier monolith
// dotenv should be configured by application entrypoint (e.g. main.js)
const express = require('express');
const axios = require('axios');
const dns = require('dns').promises; // For DNS checks
const { URL } = require('url');

// helpers and configuration are separated into modules
const config = require('./phishingConfig');
const heuristics = require('./phishingHeuristics');

// try to load tfjs only if available; otherwise fall back to noop model
let tf;
try {
  tf = require('@tensorflow/tfjs-node');
} catch (e) {
  // optional dependency; we'll use dummy model below
}

// default model loader; tries to load a TensorFlow model if tfjs-node is available,
// otherwise returns a simple logistic regression stub. Users can also inject their own
// model via options to `checkPhishing`.
async function loadModel() {
  if (tf && tf.loadLayersModel) {
    try {
      // placeholder path; in a real deployment you would provide the URL or file
      return await tf.loadLayersModel(process.env.PHISH_MODEL_PATH || 'file://model.json');
    } catch (e) {
      console.warn('unable to load TF model:', e.message);
      // fall through to stub
    }
  }

  // simple fallback
  return {
    predict: (features) => {
      const sum = features.reduce((a, b) => a + b, 0);
      return 1 / (1 + Math.exp(-sum / (features.length || 1)));
    }
  };
}

const app = express();
app.use(express.json());

// customizable patterns and configuration
let customPatterns = [];

/**
 * Update the list of custom patterns from moderation configuration.
 * @param {string[]} patterns
 */
function setCustomPatterns(patterns) {
  if (Array.isArray(patterns)) customPatterns = patterns;
}

// API keys are read lazily; store lookup helper
function getApiKey(name) {
  return process.env[name] || '';
}

async function checkPhishing(input, options = {}) {
  // options: { model?, logger?, config? }
  const { model: injectedModel, logger = console, config: userCfg = {} } = options;
  const cfg = Object.assign({}, config, userCfg);

  // early extraction
  let url = input.url || (input.message && heuristics.extractFirstUrlFromMessage(input.message));
  if (!url) {
    return { isPhishing: false, riskScore: 0, reasons: ['No URL found'] };
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return { isPhishing: true, riskScore: 100, reasons: ['Invalid URL format'] };
  }

  const hostname = parsed.hostname;
  const domain = heuristics.getDomain(hostname);
  const path = parsed.pathname || '';
  const query = parsed.search || '';

  let riskScore = 0;
  const reasons = [];
  const features = [];

  // synchronous heuristics
  if (heuristics.isIpAddress(hostname)) {
    riskScore += cfg.weights.ipAddress;
    reasons.push('URL uses IP address (potential obfuscation)');
    features.push(1);
  }

  if (cfg.urlShorteners.includes(domain)) {
    riskScore += cfg.weights.shortener;
    reasons.push('URL shortener detected (often hides phishing)');
    features.push(1);
  }

  const typos = heuristics.domainSimilarity(domain, cfg.legitDomains);
  if (typos) {
    riskScore += cfg.weights.typosquatting;
    reasons.push(`Domain similar to ${typos.match} (score ${typos.score})`);
    features.push(typos.score);
  }

  const idn = heuristics.isIdnHomograph(hostname, cfg.legitDomains);
  if (idn) {
    riskScore += cfg.weights.idnHomograph;
    reasons.push('Internationalized Domain Name (IDN) detected');
    features.push(1);
    if (idn.score) {
      riskScore += cfg.weights.idnSimilarity;
      reasons.push(`Punycode similarity to ${idn.match} (${idn.score})`);
    }
  }

  if (heuristics.hasSuspiciousTldOrDeepSubdomain(hostname, cfg.suspiciousTLDs)) {
    riskScore += cfg.weights.suspiciousTld;
    reasons.push('Suspicious TLD or deep subdomain');
    features.push(1);
  }

  const hits = heuristics.containsPhishingKeyword(path + query, cfg.phishingKeywords);
  hits.forEach(k => {
    riskScore += cfg.weights.keyword;
    reasons.push(`Phishing keyword '${k}' in URL`);
    features.push(1);
  });

  if (heuristics.isUrlLong(url)) {
    riskScore += cfg.weights.longUrl;
    reasons.push('Excessively long URL');
    features.push(url.length / 100);
  }

  if (heuristics.isNonHttps(parsed.protocol)) {
    riskScore += cfg.weights.nonHttps;
    reasons.push('Non-secure HTTP');
    features.push(1);
  }

  if (heuristics.containsAtSymbol(url)) {
    riskScore += cfg.weights.atSymbol;
    reasons.push('URL contains @');
    features.push(1);
  }

  if (heuristics.hasEncodedChars(url)) {
    riskScore += cfg.weights.encodedChars;
    reasons.push('Encoded characters in URL');
    features.push(1);
  }

  // custom patterns
  customPatterns.forEach(p => {
    try {
      const re = new RegExp(p, 'i');
      if (re.test(url) || (input.message && re.test(input.message))) {
        riskScore += cfg.weights.shortener; // reuse one weight, could be configurable
        reasons.push(`Custom pattern '${p}' matched`);
        features.push(1);
      }
    } catch (_) {
      logger.warn(`invalid custom regex: ${p}`);
    }
  });

  // asynchronous checks – DNS + remote lookups
  const asyncTasks = [];
  asyncTasks.push(
    dns.resolve(hostname)
      .then(arr => {
        if (!arr || arr.length === 0) {
          riskScore += cfg.weights.dnsFailure;
          reasons.push('No DNS resolution');
        }
      })
      .catch(() => {
        riskScore += cfg.weights.dnsFailure;
        reasons.push('DNS resolution failed');
        features.push(1);
      })
  );

  // redirect head check
  asyncTasks.push(
    axios.head(url, { maxRedirects: 5, timeout: 3000 })
      .then(resp => {
        if (resp.request.res.responseUrl && resp.request.res.responseUrl !== url) {
          riskScore += cfg.weights.redirect;
          reasons.push('URL redirects');
        }
      })
      .catch(() => {})
  );

  // optional external APIs
  const safeKey = getApiKey('SAFE_BROWSING_API_KEY');
  if (safeKey) {
    asyncTasks.push(
      axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${safeKey}`, {
        client: { clientId: 'phishingcatcher', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      })
        .then(res => {
          if (res.data.matches && res.data.matches.length > 0) {
            riskScore += cfg.weights.googleSafeBrowsing;
            reasons.push(`Flagged by Google Safe Browsing: ${res.data.matches[0].threatType}`);
          }
        })
        .catch(err => logger.debug('Safe Browsing error', err))
    );
  }

  const vtKey = getApiKey('VIRUSTOTAL_API_KEY');
  if (vtKey) {
    asyncTasks.push(
      axios
        .get(`https://www.virustotal.com/api/v3/urls/${Buffer.from(url).toString('base64url')}`, {
          headers: { 'x-apikey': vtKey }
        })
        .then(res => {
          const stats = res.data.data.attributes.last_analysis_stats || {};
          const mal = stats.malicious || 0;
          const susp = stats.suspicious || 0;
          if (mal + susp > 0) {
            riskScore += cfg.weights.virusTotal * (mal + susp);
            reasons.push(`VirusTotal: ${mal} malicious, ${susp} suspicious`);
          }
        })
        .catch(err => logger.debug('VirusTotal error', err))
    );
  }

  const phishKey = getApiKey('PHISHTANK_API_KEY');
  if (phishKey) {
    asyncTasks.push(
      axios
        .post('https://checkurl.phishtank.com/checkurl/', {
          format: 'json',
          url,
          app_key: phishKey
        })
        .then(res => {
          if (res.data.results && res.data.results.in_database && res.data.results.verified && res.data.results.valid) {
            riskScore += cfg.weights.phishTank;
            reasons.push('Confirmed phishing by PhishTank');
          }
        })
        .catch(err => logger.debug('PhishTank error', err))
    );
  }

  // wait for all async checks
  await Promise.all(asyncTasks);

  // run ML model if provided or default
  const realModel = injectedModel || (await loadModel());
  const mlProb = realModel.predict(features);
  riskScore += mlProb * 50;

  riskScore = Math.min(Math.max(riskScore, 0), 100);

  const isPhish = riskScore > (cfg.thresholds.phishingScore || 50);
  return { isPhishing: isPhish, riskScore, reasons };
}

app.post('/analyze', async (req, res) => {
  const input = req.body; // { url: '...' } or { message: '...' }
  if (!input.url && !input.message) return res.status(400).json({ error: 'URL or message required' });

  const result = await checkPhishing(input);
  if (result.isPhishing) {
    console.log(`Phishing caught: ${input.url || input.message} - Score: ${result.riskScore}`);
    // Alert: Integrate Slack, email, or DB logging here
    // e.g., await sendAlert(result);
  }

  res.json(result);
});

// only start the HTTP service when this file is executed directly
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

// export helpers and configuration so the moderation module can configure and reuse logic
module.exports = {
  app,
  checkPhishing,
  setCustomPatterns,
  config
};
