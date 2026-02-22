const { checkPhishing } = require('./modules/moderation/phishingService');

async function runTest() {
  const testUrls = [
    'http://paypal.com.example.tk/login',
    'http://xn--pypal-4ve.com',
    'http://example.com',
  ];

  for (const url of testUrls) {
    console.log(`\nTesting URL: ${url}`);
    try {
      const result = await checkPhishing({ url });
      console.log('Result:', result);
    } catch (err) {
      console.error('Error during checkPhishing:', err);
    }
  }
}

runTest();
