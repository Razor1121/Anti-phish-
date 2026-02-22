const { checkPhishing, setCustomPatterns } = require('./modules/moderation/phishingService');

(async () => {
  const urls = [
    'http://paypal.com.example.tk/login',
    'https://example.com',
    'http://192.168.0.1',
  ];

  for (const u of urls) {
    const res = await checkPhishing({ url: u });
    console.log(u, '=>', res);
  }
})();
