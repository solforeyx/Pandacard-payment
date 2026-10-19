const express = require('express');
const crypto = require('crypto');
const app = express();

// Capture the raw request body so we can verify Paystack's signature correctly.
// (JSON.stringify(req.body) is NOT safe for signature checks because whitespace/key order can differ.)
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// ==========================================
// CONFIGURATION — set these in your environment variables
// ==========================================
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

// Panda Card Supabase webhook
const PANDACARD_WEBHOOK =
  process.env.PANDACARD_WEBHOOK ||
  'https://dxxhlaxdudtiktplwvbq.supabase.co/functions/v1/deposit-webhook/paystack';

// Other site webhook (replace with your real URL once deployed)
const OTHER_SITE_WEBHOOK =
  process.env.OTHER_SITE_WEBHOOK ||
  'https://your-other-site.com/api/webhook';

// ==========================================
// ⚠️ IMPORTANT: SHOPIFY IS NOT HANDLED HERE ⚠️
// ==========================================
// Your Shopify store uses the OFFICIAL Paystack plugin inside Shopify Payments.
// That plugin automatically marks orders as paid and generates its own references.
// Do NOT route Shopify through this router — it will fail because Shopify
// expects its own HMAC (X-Shopify-Hmac-Sha256), not Paystack's signature.
// So the Shopify branch has been removed on purpose.

// ==========================================
// Health check (so you can confirm it's running in the browser)
// ==========================================
app.get('/', (req, res) => {
  res.send('Panda Paystack Router is Live and Running! 🐼');
});

// ==========================================
// Main Paystack webhook router
// ==========================================
app.post('/paystack-router', async (req, res) => {
  const payload = req.body;
  const signature = req.headers['x-paystack-signature'];

  // 1. Verify the request is genuinely from Paystack
  if (!PAYSTACK_SECRET_KEY) {
    console.error('PAYSTACK_SECRET_KEY is not set in environment variables');
    return res.status(500).send('Server misconfigured');
  }

  if (!signature || !req.rawBody) {
    console.warn('Missing signature or raw body — request rejected');
    return res.status(401).send('Invalid signature');
  }

  const expectedSignature = crypto
    .createHmac('sha512', PAYSTACK_SECRET_KEY)
    .update(req.rawBody)
    .digest('hex');

  if (expectedSignature !== signature) {
    console.warn('Invalid Paystack signature — request rejected');
    return res.status(401).send('Invalid signature');
  }

  // 2. Acknowledge to Paystack immediately so they don't retry
  res.status(200).send('Webhook Received');

  // 3. Route the event to the correct backend
  const appName = payload?.data?.metadata?.app;

  try {
    if (['pandacard', 'PandaCard', 'panda_card'].includes(appName)) {
      // ---- Panda Card Supabase backend ----
      console.log('Forwarding to Panda Card...');
      const response = await fetch(PANDACARD_WEBHOOK, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-paystack-signature': signature
        },
        body: JSON.stringify(payload)
      });
      console.log('Panda Card Response Status:', response.status);
    } else {
      // ---- Any other site ----
      console.log('Forwarding to Other Site...');
      const response = await fetch(OTHER_SITE_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      console.log('Other Site Response Status:', response.status);
    }
  } catch (error) {
    console.error('Routing Error:', error.message);
  }
});

// ==========================================
// Start the server
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Router is running on port ${PORT}`);
});