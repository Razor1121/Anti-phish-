const heuristics = require('../phishingHeuristics');
const { checkPhishing, setCustomPatterns } = require('../phishingService');

describe('phishing heuristics', () => {
  test('isIpAddress detects IPv4 and IPv6', () => {
    expect(heuristics.isIpAddress('127.0.0.1')).toBe(true);
    expect(heuristics.isIpAddress('::1')).toBe(true);
    expect(heuristics.isIpAddress('example.com')).toBe(false);
  });

  test('domainSimilarity returns info for typos', () => {
    const res = heuristics.domainSimilarity('paypal.com', ['paypal.com']);
    expect(res).toBeNull();
    const res2 = heuristics.domainSimilarity('paypa1.com', ['paypal.com']);
    expect(res2).not.toBeNull();
    expect(res2.match).toBe('paypal.com');
  });

  test('extractFirstUrlFromMessage picks a URL', () => {
    expect(heuristics.extractFirstUrlFromMessage('no link here')).toBeNull();
    expect(
      heuristics.extractFirstUrlFromMessage('visit https://example.com now')
    ).toBe('https://example.com');
  });
});

describe('checkPhishing integration', () => {
  test('flags obvious phishing link', async () => {
    const { isPhishing, reasons } = await checkPhishing({ url: 'http://paypal.com.example.tk/login' });
    expect(isPhishing).toBe(true);
    expect(reasons.some(r => r.includes('Suspicious TLD'))).toBe(true);
  });

  test('returns false for benign https site', async () => {
    const { isPhishing } = await checkPhishing({ url: 'https://example.com' });
    expect(isPhishing).toBe(false);
  });

  test('custom patterns can match', async () => {
    setCustomPatterns(['evil']);
    const { isPhishing, reasons } = await checkPhishing({ url: 'https://good.com/evil' });
    expect(isPhishing).toBe(true);
    expect(reasons.some(r => r.includes('Custom pattern'))).toBe(true);
  });

  test('override configuration works', async () => {
    // artificially lower threshold so non-secure example flags
    const { isPhishing } = await checkPhishing(
      { url: 'https://example.com' },
      { config: { thresholds: { phishingScore: 0 } } }
    );
    expect(isPhishing).toBe(true);
  });
});
