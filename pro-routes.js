/* ============================================================
   Jewellery Store PRO — Pro Module (v2)
   Adds on top of core server.js WITHOUT breaking core flows:
   • Mobile OTP login (Dev / MSG91 / Twilio) + Google Login
   • Razorpay (UPI/Cards/EMI) + COD support, verify + webhook
   • Live metal-rate weight pricing engine (Gold/Silver)
   • Image upload (Admin), Staff roles, Shipping + Returns
   • CSV exports, Buyer Setup-Status (for reselling/white-label)
   Config comes only from .env — secrets are never sent to browser.
   ============================================================ */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const nodemailer = require('nodemailer');

module.exports = function registerPro(ctx) {
  const { app, getDB, saveDB, auth, adminOnly, publicUser, sign, uid, normPhone, cartDetailed } = ctx;
  const db = () => getDB();
  const env = (k, d = '') => (process.env[k] == null || process.env[k] === '' ? d : process.env[k]);
  const isTestPayments = () => String(env('PAYMENTS_TEST_MODE', 'true')) === 'true' && !env('RAZORPAY_KEY_ID');
  const pendingPay = new Map(); // razorpayOrderId -> {userId, amount, at}
  const otpHits = new Map();    // phone -> lastSentTs

  /* ---------- Pricing engine ----------
     Formula (standard jeweller): (Metal + Making + Stone) + GST 3%
     Making can be % of metal, per-gram, or flat (stored as makingType/value). */
  function rateFor(purity = '') {
    const s = db().settings || {};
    const p = String(purity).toUpperCase();
    if (p.includes('24K') || p.includes('999')) return +s.gold24k || 9760;
    if (p.includes('18K')) return Math.round((+s.gold22k || 8945) * 18 / 22);
    if (p.includes('925') || p.includes('SILVER')) return +s.silver || 112;
    return +s.gold22k || 8945; // default 22K
  }
  function computePricing(p) {
    if (!p || p.pricingMode !== 'weight') return null;
    const grams = +p.netWeightGrams || 0;
    const rate = rateFor(p.purity);
    const metal = Math.round(grams * rate);
    let making = 0;
    if (p.makingType === 'perGram') making = Math.round(grams * (+p.makingValue || 0));
    else if (p.makingType === 'flat') making = Math.round(+p.makingValue || 0);
    else making = Math.round(metal * (+p.makingValue || 12) / 100); // percent default
    const stone = Math.round(+p.stoneCharges || 0);
    const subtotal = metal + making + stone;
    const gst = Math.round(subtotal * 0.03);
    return { grams, rate, metal, making, stone, gst, total: subtotal + gst };
  }
  function refreshWeightPrices(save = true) {
    let changed = 0;
    (db().products || []).forEach(p => {
      const c = computePricing(p);
      if (c && (p.price !== c.total || JSON.stringify(p.priceBreakup) !== JSON.stringify(c))) {
        p.price = c.total; p.priceBreakup = c; if (!p.mrp || p.mrp < p.price) p.mrp = p.price; changed++;
      }
    });
    if (save && changed) saveDB();
    return changed;
  }

  /* ---------- Migration (safe on every update: never deletes buyer data) ---------- */
  function migrate() {
    const d = db(); if (!d) return;
    d.settings = Object.assign({ gstin: '', storeState: 'Gujarat', ratesUpdatedAt: null, codEnabled: true }, d.settings);
    if (!Array.isArray(d.otps)) d.otps = [];
    (d.products || []).forEach(p => { if (!p.pricingMode) { p.pricingMode = 'fixed'; p.netWeightGrams = parseFloat(p.weight) || 0; p.makingType = 'percent'; p.makingValue = 12; p.stoneCharges = 0; p.sku = p.sku || ('SKU-' + String(p.id).toUpperCase()); } });
    (d.orders || []).forEach(o => { if (!o.shippingInfo) o.shippingInfo = { courier: '', awb: '', expectedDate: '' }; if (!o.returnInfo) o.returnInfo = null; });
    // Demo staff account (can be deleted by admin)
    if (!d.users.some(u => u.email === 'staff@sonara.in')) {
      d.users.push({ id: 'u_staff', name: 'Staff — Store Assistant', email: 'staff@sonara.in', phone: '9000000001', password: bcrypt.hashSync('staff123', 10), role: 'staff', active: true, createdAt: new Date().toISOString() });
    }
    refreshWeightPrices(false);
    saveDB();
    console.log('✨ Pro module ready (OTP/Google, Razorpay+COD, live pricing, staff, shipping/returns)');
  }
  global.__jewelProMigrate = migrate;

  const staffOrAdmin = (req, res, next) => { if (['admin', 'staff'].includes(req.user.role)) return next(); return res.status(403).json({ error: 'Staff/Admin access required' }); };

  /* ---------- Public config (NO secrets — only public IDs + modes) ---------- */
  app.get('/api/config/public', (req, res) => {
    res.json({
      storeName: db().settings.storeName,
      googleClientId: env('GOOGLE_CLIENT_ID'),
      razorpayKeyId: env('RAZORPAY_KEY_ID'),
      paymentsMode: env('RAZORPAY_KEY_ID') ? 'razorpay' : (String(env('PAYMENTS_TEST_MODE', 'true')) === 'true' ? 'test' : 'cod-only'),
      otpDevMode: String(env('OTP_DEV_MODE', 'true')) === 'true',
      codEnabled: db().settings.codEnabled !== false,
      proVersion: '2.0.0'
    });
  });

  /* ---------- Buyer Setup Status (admin only, booleans only) ---------- */
  app.get('/api/admin/setup-status', auth, adminOnly, (req, res) => {
    const s = db().settings;
    const checks = [
      { key: 'jwt', label: 'JWT Secret changed from default', ok: !!process.env.JWT_SECRET && !String(process.env.JWT_SECRET).includes('dev-only') && !String(process.env.JWT_SECRET).includes('CHANGE'), fix: 'Set a long random JWT_SECRET in .env (different for every buyer)' },
      { key: 'razorpay', label: 'Razorpay Keys (UPI/Cards/EMI)', ok: !!env('RAZORPAY_KEY_ID') && !!env('RAZORPAY_KEY_SECRET'), fix: 'Razorpay Dashboard → Settings → API Keys → paste in .env, restart server' },
      { key: 'otp', label: 'OTP SMS Provider (MSG91/Twilio) or Dev Mode OFF', ok: (!!env('MSG91_AUTH_KEY') || !!env('TWILIO_ACCOUNT_SID')) && String(env('OTP_DEV_MODE')) !== 'true', fix: 'Add MSG91/Twilio keys in .env and set OTP_DEV_MODE=false before launch' },
      { key: 'google', label: 'Google Login Client ID', ok: !!env('GOOGLE_CLIENT_ID'), fix: 'Google Cloud Console → OAuth Client (Web) → paste GOOGLE_CLIENT_ID in .env' },
      { key: 'rates', label: 'Gold/Silver rates updated', ok: !!s.ratesUpdatedAt, fix: 'Admin → Setup & Rates → update today\'s rates (weight-priced items auto-update)' },
      { key: 'gstin', label: 'Store GSTIN for invoices', ok: !!s.gstin, fix: 'Admin → Settings → add GSTIN + store state' },
      { key: 'testpay', label: 'Test Payments OFF (production safety)', ok: !(String(env('PAYMENTS_TEST_MODE', 'true')) === 'true' && !env('RAZORPAY_KEY_ID')), fix: 'Add Razorpay keys, then set PAYMENTS_TEST_MODE=false' },
    ];
    res.json({ checks, readyPercent: Math.round(checks.filter(c => c.ok).length / checks.length * 100), counts: { products: db().products.length, orders: db().orders.length, users: db().users.length }, ratesUpdatedAt: s.ratesUpdatedAt, settings: { gold22k: s.gold22k, gold24k: s.gold24k, silver: s.silver, gstin: s.gstin || '', storeState: s.storeState || '' } });
  });

  /* ---------- Mobile OTP ---------- */
  const hashOtp = (phone, otp) => crypto.createHash('sha256').update(phone + ':' + otp + ':' + (process.env.JWT_SECRET || 'x')).digest('hex');
  async function sendSmsOtp(phone, otp) {
    if (env('MSG91_AUTH_KEY') && env('MSG91_TEMPLATE_ID')) {
      const r = await fetch('https://control.msg91.com/api/v5/otp?template_id=' + encodeURIComponent(env('MSG91_TEMPLATE_ID')) + '&mobile=91' + phone + '&otp=' + otp, { method: 'POST', headers: { authkey: env('MSG91_AUTH_KEY'), 'Content-Type': 'application/json' } });
      if (!r.ok) throw new Error('MSG91 failed (' + r.status + ')');
      return 'msg91';
    }
    if (env('TWILIO_ACCOUNT_SID') && env('TWILIO_AUTH_TOKEN') && env('TWILIO_FROM')) {
      const body = new URLSearchParams({ To: '+91' + phone, From: env('TWILIO_FROM'), Body: `Your ${db().settings.storeName} OTP is ${otp}. Valid 5 minutes. Do not share.` });
      const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env('TWILIO_ACCOUNT_SID')}/Messages.json`, { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(env('TWILIO_ACCOUNT_SID') + ':' + env('TWILIO_AUTH_TOKEN')).toString('base64') }, body });
      if (!r.ok) throw new Error('Twilio failed (' + r.status + ')');
      return 'twilio';
    }
    console.log(`📱 [OTP-DEV] OTP for +91${phone} is ${otp} (configure MSG91/Twilio in .env for real SMS)`);
    return 'dev-console';
  }
  // Email OTP (FREE via Gmail SMTP) — no SMS cost, works immediately
  const hashEmailOtp = (email, otp) => crypto.createHash('sha256').update(email + ':' + otp + ':' + (process.env.JWT_SECRET || 'x')).digest('hex');
  async function sendEmailOtp(email, otp) {
    const host = env('SMTP_HOST'), user = env('SMTP_USER'), pass = env('SMTP_PASS');
    if (!host || !user || !pass) {
      console.log(`📧 [EMAIL-OTP-DEV] OTP for ${email} is ${otp} (configure SMTP in .env for real email)`);
      return 'dev-console';
    }
    const transporter = nodemailer.createTransport({
      host, port: +(env('SMTP_PORT') || 587), secure: +(env('SMTP_PORT') || 587) === 465,
      auth: { user, pass },
    });
    const storeName = db().settings.storeName || 'Sonara Jewels';
    await transporter.sendMail({
      from: env('MAIL_FROM') || user,
      to: email,
      subject: `Your ${storeName} login OTP: ${otp}`,
      text: `Your ${storeName} OTP is ${otp}. Valid for 5 minutes. Do not share this code with anyone.`,
      html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px;border:1px solid #e5e7eb;border-radius:12px">
        <h2 style="color:#8a2432;margin:0 0 8px">${storeName}</h2>
        <p>Your login OTP is:</p>
        <div style="font-size:32px;font-weight:800;letter-spacing:6px;text-align:center;padding:16px;background:#f9fafb;border-radius:10px;margin:16px 0">${otp}</div>
        <p style="color:#6b7280;font-size:13px">Valid for 5 minutes. Do not share this code with anyone.</p>
      </div>`,
    });
    return 'email';
  }
  app.post('/api/auth/otp/send', async (req, res) => {
    const phone = normPhone((req.body || {}).phone || '');
    if (phone.length !== 10) return res.status(400).json({ error: 'Enter a valid 10-digit mobile number' });
    const last = otpHits.get(phone) || 0;
    if (Date.now() - last < 45 * 1000) return res.status(429).json({ error: 'Please wait 45 seconds before resending OTP' });
    otpHits.set(phone, Date.now());
    const otp = String(100000 + Math.floor(Math.random() * 900000));
    const d = db(); d.otps = (d.otps || []).filter(o => o.phone !== phone && Date.now() < o.expires);
    d.otps.push({ phone, hash: hashOtp(phone, otp), expires: Date.now() + 10 * 60 * 1000, attempts: 0 });
    saveDB();
    try {
      const via = await sendSmsOtp(phone, otp);
      const out = { sent: true, via, expiresInSec: 300 };
      if (String(env('OTP_DEV_MODE', 'true')) === 'true') out.devOtp = otp; // testing only
      res.json(out);
    } catch (e) { res.status(502).json({ error: 'Could not send OTP: ' + e.message }); }
  });
  app.post('/api/auth/otp/verify', (req, res) => {
    const phone = normPhone((req.body || {}).phone || '');
    const otp = String((req.body || {}).otp || '');
    const name = (req.body || {}).name || '';
    const d = db();
    const rec = (d.otps || []).find(o => o.phone === phone);
    if (!rec || Date.now() > rec.expires) return res.status(400).json({ error: 'OTP expired. Please request a new OTP.' });
    if (rec.attempts >= 5) return res.status(429).json({ error: 'Too many wrong attempts. Request a new OTP.' });
    if (rec.hash !== hashOtp(phone, otp)) { rec.attempts++; saveDB(); return res.status(401).json({ error: 'Wrong OTP. Please check and try again.' }); }
    d.otps = d.otps.filter(o => o.phone !== phone);
    let user = d.users.find(u => normPhone(u.phone) === phone);
    if (user && !user.active) return res.status(403).json({ error: 'Your account has been blocked. Please contact support.' });
    if (!user) {
      user = { id: uid('u'), name: name || ('Customer ' + phone.slice(-4)), email: phone + '@otp.local', phone, password: bcrypt.hashSync(uid('pw') + phone, 10), role: 'customer', active: true, createdAt: new Date().toISOString(), viaOtp: true };
      d.users.push(user);
    }
    saveDB();
    res.json({ token: sign(user), user: publicUser(user) });
  });

  /* ---------- Google Login ---------- */
  /* ---------- Email OTP (FREE) ---------- */
  const emailOtpHits = new Map();
  app.post('/api/auth/otp/email-send', async (req, res) => {
    const email = String((req.body || {}).email || '').trim().toLowerCase();
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address' });
    const last = emailOtpHits.get(email) || 0;
    if (Date.now() - last < 45 * 1000) return res.status(429).json({ error: 'Please wait 45 seconds before resending' });
    emailOtpHits.set(email, Date.now());
    const otp = String(100000 + Math.floor(Math.random() * 900000));
    const d = db(); d.emailOtps = (d.emailOtps || []).filter(o => o.email !== email && Date.now() < o.expires);
    d.emailOtps.push({ email, hash: hashEmailOtp(email, otp), expires: Date.now() + 10 * 60 * 1000, attempts: 0 });
    saveDB();
    try {
      const via = await sendEmailOtp(email, otp);
      const out = { sent: true, via, expiresInSec: 300 };
      if (String(env('OTP_DEV_MODE', 'true')) === 'true' && via === 'dev-console') out.devOtp = otp;
      res.json(out);
    } catch (e) { res.status(502).json({ error: 'Could not send email: ' + e.message }); }
  });
  app.post('/api/auth/otp/email-verify', (req, res) => {
    const email = String((req.body || {}).email || '').trim().toLowerCase();
    const otp = String((req.body || {}).otp || '').trim();
    const name = String((req.body || {}).name || '').trim();
    const d = db();
    const rec = (d.emailOtps || []).find(o => o.email === email && Date.now() < o.expires);
    if (!rec) return res.status(400).json({ error: 'OTP expired or not sent. Please request a new one.' });
    if (rec.attempts >= 5) return res.status(429).json({ error: 'Too many wrong attempts. Request a new OTP.' });
    if (rec.hash !== hashEmailOtp(email, otp)) { rec.attempts++; saveDB(); return res.status(401).json({ error: `Wrong OTP. ${5 - rec.attempts} attempt(s) left.`, attemptsLeft: 5 - rec.attempts }); }
    d.emailOtps = d.emailOtps.filter(o => o.email !== email);
    let user = d.users.find(u => u.email.toLowerCase() === email);
    if (user && !user.active) return res.status(403).json({ error: 'Your account has been blocked. Please contact support.' });
    if (!user) {
      user = { id: uid('u'), name: name || email.split('@')[0], email, phone: '', password: bcrypt.hashSync(uid('pw') + email, 10), role: 'customer', active: true, createdAt: new Date().toISOString(), viaEmailOtp: true };
      d.users.push(user);
    }
    saveDB();
    res.json({ token: sign(user), user: publicUser(user), needsPhone: !user.phone });
  });

  app.post('/api/auth/google', async (req, res) => {
    const clientId = env('GOOGLE_CLIENT_ID');
    if (!clientId) return res.status(501).json({ error: 'Google Login is not configured yet. Admin: add GOOGLE_CLIENT_ID in .env (see Setup page).' });
    const credential = (req.body || {}).credential || (req.body || {}).idToken || '';
    if (!credential) return res.status(400).json({ error: 'Google credential missing' });
    try {
      const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(credential));
      const info = await r.json();
      if (!r.ok || info.aud !== clientId || !info.email) return res.status(401).json({ error: 'Google sign-in could not be verified. Please try again.' });
      if (String(info.email_verified) !== 'true') return res.status(401).json({ error: 'Google email is not verified.' });
      const d = db();
      let user = d.users.find(u => u.email.toLowerCase() === String(info.email).toLowerCase());
      if (user && !user.active) return res.status(403).json({ error: 'Your account has been blocked. Please contact support.' });
      if (!user) {
        user = { id: uid('u'), name: info.name || info.email.split('@')[0], email: String(info.email).toLowerCase(), phone: '', password: bcrypt.hashSync(uid('pw') + info.sub, 10), role: 'customer', active: true, createdAt: new Date().toISOString(), viaGoogle: true };
        d.users.push(user); saveDB();
      }
      res.json({ token: sign(user), user: publicUser(user), needsPhone: !user.phone });
    } catch (e) { res.status(502).json({ error: 'Google verification failed: ' + e.message }); }
  });

  /* ---------- Razorpay + COD payments ---------- */
  function checkoutTotal(userId, couponCode) {
    const cart = cartDetailed(userId);
    let discount = 0;
    if (couponCode) {
      const c = db().coupons.find(x => x.code === String(couponCode).toUpperCase() && x.active);
      if (c && cart.subtotal >= c.minOrder) discount = Math.min(c.type === 'percent' ? Math.floor(cart.subtotal * c.value / 100) : c.value, c.maxDiscount || 999999);
    }
    const shipping = cart.count === 0 ? 0 : ((cart.subtotal - discount) >= db().settings.freeShipAbove ? 0 : db().settings.shippingFee);
    return { cart, discount, shipping, total: cart.subtotal - discount + shipping };
  }
  app.post('/api/payments/razorpay/order', auth, async (req, res) => {
    refreshWeightPrices();
    const { total, cart } = checkoutTotal(req.user.id, (req.body || {}).coupon || '');
    if (!cart.items.length) return res.status(400).json({ error: 'Your cart is empty' });
    const amountPaise = Math.round(total * 100);
    if (!env('RAZORPAY_KEY_ID') || !env('RAZORPAY_KEY_SECRET')) {
      if (!isTestPayments()) return res.status(501).json({ error: 'Online payment is not configured. Please choose COD or contact the store.' });
      const mockId = 'order_TEST' + Date.now().toString(36);
      pendingPay.set(mockId, { userId: req.user.id, amount: total, at: Date.now() });
      return res.json({ mock: true, id: mockId, amount: amountPaise, currency: 'INR', total, note: 'TEST MODE — no real money. Add Razorpay keys in .env for live payments.' });
    }
    try {
      const r = await fetch('https://api.razorpay.com/v1/orders', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Basic ' + Buffer.from(env('RAZORPAY_KEY_ID') + ':' + env('RAZORPAY_KEY_SECRET')).toString('base64') },
        body: JSON.stringify({ amount: amountPaise, currency: 'INR', receipt: 'rcpt_' + Date.now().toString(36), notes: { userId: req.user.id } })
      });
      const data = await r.json();
      if (!r.ok) return res.status(502).json({ error: 'Razorpay order failed: ' + (data.error && data.error.description || r.status) });
      pendingPay.set(data.id, { userId: req.user.id, amount: total, at: Date.now() });
      res.json({ mock: false, id: data.id, amount: data.amount, currency: data.currency, total, keyId: env('RAZORPAY_KEY_ID') });
    } catch (e) { res.status(502).json({ error: 'Payment gateway unreachable: ' + e.message }); }
  });
  app.post('/api/payments/razorpay/verify', auth, (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, mockSuccess } = req.body || {};
    if (!razorpay_order_id || !pendingPay.has(razorpay_order_id)) return res.status(400).json({ error: 'Unknown payment session. Please retry checkout.' });
    if (String(razorpay_order_id).startsWith('order_TEST')) {
      if (!isTestPayments()) return res.status(400).json({ error: 'Test payments are disabled.' });
      if (!mockSuccess) return res.status(400).json({ error: 'Test payment was cancelled/failed.' });
      pendingPay.delete(razorpay_order_id);
      return res.json({ verified: true, mock: true, paymentId: 'pay_TEST' + Date.now().toString(36) });
    }
    const expected = crypto.createHmac('sha256', env('RAZORPAY_KEY_SECRET')).update(razorpay_order_id + '|' + razorpay_payment_id).digest('hex');
    if (expected !== razorpay_signature) return res.status(400).json({ error: 'Payment verification failed. If money was deducted, it will auto-refund; please contact support with your payment ID.' });
    pendingPay.delete(razorpay_order_id);
    res.json({ verified: true, mock: false, paymentId: razorpay_payment_id });
  });
  app.post('/api/payments/webhook', (req, res) => {
    // Verify signature on RAW body (Razorpay signs exact bytes)
    const secret = env('RAZORPAY_WEBHOOK_SECRET');
    if (secret) {
      const sig = req.headers['x-razorpay-signature'] || '';
      const raw = req.rawBody || Buffer.from(JSON.stringify(req.body || {}));
      const expected = crypto.createHmac('sha256', secret).update(raw).digest('hex');
      if (sig !== expected) {
        console.warn('⚠️ Razorpay webhook signature mismatch — rejecting');
        return res.status(400).json({ error: 'Invalid signature' });
      }
    }
    const event = (req.body && req.body.event) || 'unknown';
    console.log('🔔 Razorpay webhook:', event);
    // Process payment events: mark order paid
    try {
      const payload = (req.body && req.body.payload) || {};
      const payment = payload.payment && payload.payment.entity;
      const rzpOrderId = payment && payment.order_id;
      if (rzpOrderId && pendingPay.has(rzpOrderId)) {
        const pend = pendingPay.get(rzpOrderId);
        const order = db().orders.find(o => o.paymentRef && o.paymentRef.orderId === rzpOrderId);
        if (order && event === 'payment.captured') {
          order.paymentStatus = 'Paid';
          order.paymentRef.paymentId = payment.id;
          order.timeline.push({ s: 'Paid', t: new Date().toISOString() });
          saveDB();
          console.log('✅ Webhook: order', order.id, 'marked Paid via', payment.id);
        }
        pendingPay.delete(rzpOrderId);
      }
    } catch (e) { console.warn('Webhook processing error:', e.message); }
    res.json({ received: true });
  });
  app.post('/api/orders/:id/payment-ref', auth, (req, res) => {
    const o = db().orders.find(x => x.id === req.params.id);
    if (!o) return res.status(404).json({ error: 'Order not found' });
    if (o.userId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Not your order' });
    o.paymentRef = { provider: 'razorpay', paymentId: (req.body || {}).paymentId || '', orderId: (req.body || {}).orderId || '', mock: !!(req.body || {}).mock, at: new Date().toISOString() };
    saveDB(); res.json({ ok: true });
  });

  /* ---------- Live rates + product pricing ---------- */
  app.post('/api/admin/rates', auth, adminOnly, (req, res) => {
    const s = db().settings;
    ['gold22k', 'gold24k', 'silver'].forEach(k => { if (req.body[k] != null && +req.body[k] >= 0) s[k] = +req.body[k]; });
    if (req.body.rateMargin != null) s.rateMargin = +req.body.rateMargin || 0;
    if (req.body.autoRates != null) s.autoRates = !!req.body.autoRates;
    s.ratesSource = 'manual';
    s.ratesUpdatedAt = new Date().toISOString();
    const changed = refreshWeightPrices(false);
    saveDB();
    res.json({ settings: s, repriced: changed, message: `Rates updated. ${changed} live-price product(s) repriced.` });
  });

  /* ---------- Auto gold-rate fetching (gold-api.com, free) ---------- */
  const TROY_GRAM = 31.1035;
  async function fetchLiveRates() {
    const [g, sil] = await Promise.all([
      fetch('https://api.gold-api.com/price/XAU/INR').then(r => r.json()),
      fetch('https://api.gold-api.com/price/XAG/INR').then(r => r.json()),
    ]);
    if (!g.price || !sil.price) throw new Error('Market API returned no prices');
    const s = db().settings;
    const margin = +s.rateMargin || 0; // admin-adjustable ₹/gram difference vs international rate
    const g24 = Math.round(g.price / TROY_GRAM + margin);
    const g22 = Math.round(g24 * 22 / 24);
    const silver = Math.round(sil.price / TROY_GRAM + margin);
    s.gold24k = g24; s.gold22k = g22; s.silver = silver;
    s.ratesSource = 'api';
    s.ratesUpdatedAt = new Date().toISOString();
    const changed = refreshWeightPrices(false);
    saveDB();
    console.log(`⚖️ Live rates fetched: 24K ₹${g24}/g, 22K ₹${g22}/g, Silver ₹${silver}/g (${changed} products repriced)`);
    return { gold24k: g24, gold22k: g22, silver, repriced: changed };
  }
  app.post('/api/admin/rates/refresh', auth, adminOnly, async (req, res) => {
    try {
      const r = await fetchLiveRates();
      res.json({ ok: true, ...r, message: `Live rates fetched: 22K ₹${r.gold22k}/g, 24K ₹${r.gold24k}/g, Silver ₹${r.silver}/g. ${r.repriced} product(s) repriced.` });
    } catch (e) {
      res.status(502).json({ error: 'Could not fetch live rates right now. Check internet connection and try again.' });
    }
  });
  // Auto-update: on startup + every 6 hours (if enabled in settings)
  const autoRateTick = () => { if (db().settings.autoRates !== false) fetchLiveRates().catch(e => console.warn('⚠️ Auto rate fetch failed:', e.message)); };
  setTimeout(autoRateTick, 15000); // 15s after startup
  setInterval(autoRateTick, 6 * 60 * 60 * 1000); // every 6 hours
  app.get('/api/pricing/preview', auth, staffOrAdmin, (req, res) => {
    const fake = { pricingMode: 'weight', netWeightGrams: +req.query.grams || 0, purity: req.query.purity || '22K BIS Hallmarked', makingType: req.query.makingType || 'percent', makingValue: +req.query.makingValue || 12, stoneCharges: +req.query.stoneCharges || 0 };
    res.json(computePricing(fake));
  });
  app.put('/api/admin/products/:id/pricing', auth, staffOrAdmin, (req, res) => {
    const p = db().products.find(x => x.id === req.params.id);
    if (!p) return res.status(404).json({ error: 'Product not found' });
    const b = req.body || {};
    if (b.pricingMode) p.pricingMode = b.pricingMode === 'weight' ? 'weight' : 'fixed';
    if (b.netWeightGrams != null) { p.netWeightGrams = +b.netWeightGrams || 0; p.weight = p.netWeightGrams ? (p.netWeightGrams + ' g') : p.weight; }
    if (b.makingType) p.makingType = b.makingType;
    if (b.makingValue != null) p.makingValue = +b.makingValue || 0;
    if (b.stoneCharges != null) p.stoneCharges = +b.stoneCharges || 0;
    if (b.sku != null) p.sku = b.sku;
    if (p.pricingMode === 'weight') { const c = computePricing(p); if (c) { p.price = c.total; p.priceBreakup = c; if (!p.mrp || p.mrp < p.price) p.mrp = p.price; } }
    else delete p.priceBreakup;
    saveDB(); res.json(p);
  });

  /* ---------- Bulk product import (CSV parsed in browser → JSON rows) ----------
     Upsert by SKU: existing SKU = update, new SKU = create. Weight-mode rows get live prices. */
  app.post('/api/admin/products/import', auth, adminOnly, (req, res) => {
    const rows = Array.isArray(req.body && req.body.rows) ? req.body.rows : null;
    if (!rows || !rows.length) return res.status(400).json({ error: 'No rows received. Upload a CSV file with product rows.' });
    if (rows.length > 500) return res.status(400).json({ error: 'Max 500 products per import. Split the file and try again.' });
    const METALS = ['Gold', 'Silver', 'Imitation'];
    let created = 0, updated = 0; const errors = [];
    rows.forEach((r, idx) => {
      const rowNo = idx + 2; // header = row 1
      try {
        const norm = {}; Object.keys(r || {}).forEach(k => norm[k.toLowerCase().replace(/[^a-z]/g, '')] = String(r[k] == null ? '' : r[k]).trim());
        const get = k => norm[k] || '';
        const name = get('name'); if (name.length < 3) throw new Error('Product name missing/short');
        const metal = METALS.find(m => m.toLowerCase() === get('metal').toLowerCase()); if (!metal) throw new Error('Metal must be Gold, Silver or Imitation');
        const category = get('category'); if (!category) throw new Error('Category missing');
        const sku = get('sku');
        const mode = get('pricingmode').toLowerCase() === 'weight' ? 'weight' : 'fixed';
        const existing = sku ? db().products.find(p => String(p.sku || '').toLowerCase() === sku.toLowerCase()) : null;
        const base = existing || { id: uid('p'), rating: 4.5, reviewsCount: 0, sold: 0, stock: 10, isFeatured: false, isNew: false, isBestseller: false, active: true, archived: false, images: [], createdAt: new Date().toISOString() };
        base.name = name; base.metal = metal; base.category = category;
        base.purity = get('purity') || base.purity || (metal === 'Gold' ? '22K BIS Hallmarked' : metal === 'Silver' ? '925 Sterling Silver' : 'Premium Gold-Plated (Imitation)');
        base.weight = get('weight') || base.weight || '—';
        base.image = get('image') || base.image || '/images/p12.jpg';
        base.sku = sku || base.sku || ('SKU-' + base.id.replace(/[^a-z0-9]/gi, '').toUpperCase());
        base.hsn = get('hsn') || base.hsn || '7113';
        if (get('stock') !== '') base.stock = Math.max(0, parseInt(get('stock'), 10) || 0);
        base.pricingMode = mode;
        base.netWeightGrams = +get('netweightgrams') || parseFloat(base.weight) || base.netWeightGrams || 0;
        if (['percent', 'pergram', 'flat'].includes(get('makingtype').toLowerCase())) base.makingType = get('makingtype').toLowerCase() === 'pergram' ? 'perGram' : get('makingtype').toLowerCase();
        if (get('makingvalue') !== '') base.makingValue = +get('makingvalue') || 0; else if (base.makingValue == null) base.makingValue = 12;
        if (get('stonecharges') !== '') base.stoneCharges = +get('stonecharges') || 0;
        base.description = get('description') || base.description || '';
        let price = Math.round(+get('price') || 0);
        if (mode === 'weight') { const c = computePricing(base); if (!c || !c.total) throw new Error('Live-weight pricing needs NetWeightGrams'); price = c.total; base.priceBreakup = c; if (base.netWeightGrams) base.weight = base.netWeightGrams + ' g'; }
        else delete base.priceBreakup;
        if (!(price > 0)) throw new Error('Price must be more than 0');
        base.price = price;
        base.mrp = Math.max(price, Math.round(+get('mrp') || base.mrp || price));
        base.updatedAt = new Date().toISOString();
        if (existing) updated++; else { db().products.unshift(base); created++; }
      } catch (e) { errors.push({ row: rowNo, error: e.message }); }
    });
    saveDB();
    res.json({ created, updated, failed: errors.length, errors: errors.slice(0, 20), message: `Import finished: ${created} added, ${updated} updated, ${errors.length} failed.` });
  });

  /* ---------- Image upload (Admin/Staff) ---------- */
  const uploadDir = path.join(__dirname, 'public', 'uploads');
  fs.mkdirSync(uploadDir, { recursive: true });
  const MIME_EXT = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp' };
  const upload = multer({
    storage: multer.diskStorage({ destination: uploadDir, filename: (req, file, cb) => cb(null, Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 7) + (MIME_EXT[file.mimetype] || '.img')) }),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => MIME_EXT[file.mimetype] ? cb(null, true) : cb(new Error('Only JPG/PNG/WebP images allowed'))
  });
  app.post('/api/upload', auth, staffOrAdmin, (req, res) => {
    upload.single('image')(req, res, (err) => {
      if (err) return res.status(400).json({ error: err.message });
      if (!req.file) return res.status(400).json({ error: 'No image received' });
      res.status(201).json({ url: '/uploads/' + req.file.filename });
    });
  });

  /* ---------- Staff/Customer creation by Admin ---------- */
  app.post('/api/admin/users', auth, adminOnly, (req, res) => {
    const { name, email, phone, password, role } = req.body || {};
    if (!name || !email || !phone || !password) return res.status(400).json({ error: 'Name, email, phone and password are required' });
    const ph = normPhone(phone);
    if (ph.length !== 10) return res.status(400).json({ error: 'Enter a valid 10-digit mobile number' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const d = db();
    if (d.users.some(u => u.email.toLowerCase() === String(email).toLowerCase())) return res.status(409).json({ error: 'Email already registered' });
    if (d.users.some(u => normPhone(u.phone) === ph)) return res.status(409).json({ error: 'Mobile number already registered' });
    const user = { id: uid('u'), name, email: String(email).toLowerCase(), phone: ph, password: bcrypt.hashSync(String(password), 10), role: ['admin', 'staff', 'customer'].includes(role) ? role : 'customer', active: true, createdAt: new Date().toISOString() };
    d.users.push(user); saveDB();
    res.status(201).json(publicUser(user));
  });
  // Staff-friendly order list (core /api/orders gives staff only own orders)
  app.get('/api/pro/orders', auth, staffOrAdmin, (req, res) => {
    let list = [...db().orders];
    if (req.query.status) list = list.filter(o => o.status === req.query.status);
    if (req.query.q) { const s = String(req.query.q).toLowerCase(); list = list.filter(o => (o.id + ' ' + o.customerName + ' ' + o.email + ' ' + o.phone).toLowerCase().includes(s)); }
    res.json(list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
  });

  /* ---------- Shipping + Returns ---------- */
  app.put('/api/orders/:id/shipping', auth, staffOrAdmin, (req, res) => {
    const o = db().orders.find(x => x.id === req.params.id);
    if (!o) return res.status(404).json({ error: 'Order not found' });
    o.shippingInfo = { courier: (req.body || {}).courier || '', awb: (req.body || {}).awb || '', expectedDate: (req.body || {}).expectedDate || '' };
    if (o.shippingInfo.awb && ['Pending', 'Processing'].includes(o.status)) { o.status = 'Shipped'; o.timeline.push({ s: 'Shipped', t: new Date().toISOString() }); }
    saveDB(); res.json(o);
  });
  app.post('/api/orders/:id/return-request', auth, (req, res) => {
    const o = db().orders.find(x => x.id === req.params.id);
    if (!o) return res.status(404).json({ error: 'Order not found' });
    if (o.userId !== req.user.id) return res.status(403).json({ error: 'Not your order' });
    if (o.status !== 'Delivered') return res.status(400).json({ error: 'Returns can be requested only after delivery.' });
    if (o.returnInfo && o.returnInfo.status === 'Requested') return res.status(400).json({ error: 'Return already requested. Our team will contact you.' });
    o.returnInfo = { status: 'Requested', reason: (req.body || {}).reason || 'Not specified', requestedAt: new Date().toISOString() };
    saveDB(); res.json(o);
  });
  app.put('/api/orders/:id/return-decision', auth, adminOnly, (req, res) => {
    const o = db().orders.find(x => x.id === req.params.id);
    if (!o) return res.status(404).json({ error: 'Order not found' });
    if (!o.returnInfo || o.returnInfo.status !== 'Requested') return res.status(400).json({ error: 'No pending return request on this order.' });
    const approve = !!(req.body || {}).approve, restock = (req.body || {}).restock !== false;
    if (approve) {
      o.returnInfo.status = 'Approved — Refund Processed (demo gateway step)';
      o.status = 'Returned'; o.paymentStatus = o.payment === 'COD' ? 'Closed (COD returned)' : 'Refunded';
      o.timeline.push({ s: 'Returned', t: new Date().toISOString() });
      if (restock) o.items.forEach(it => { const p = db().products.find(x => x.id === it.productId); if (p) { p.stock += it.qty; p.sold = Math.max(0, p.sold - it.qty); } });
    } else o.returnInfo.status = 'Rejected — ' + ((req.body || {}).note || 'Does not meet return policy');
    o.returnInfo.decidedAt = new Date().toISOString();
    saveDB(); res.json(o);
  });

  /* ---------- CSV Exports (Admin) ---------- */
  const csvCell = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
  function sendCsv(res, filename, rows) {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.send(rows.map(r => r.map(csvCell).join(',')).join('\n'));
  }
  app.get('/api/admin/export/orders.csv', auth, adminOnly, (req, res) => {
    const rows = [['OrderID', 'Date', 'Customer', 'Phone', 'Email', 'Items', 'Subtotal', 'Discount', 'Shipping', 'Total', 'Payment', 'PaymentStatus', 'Status', 'Coupon', 'Address']];
    db().orders.forEach(o => rows.push([o.id, o.createdAt, o.customerName, o.phone, o.email, o.items.map(i => i.name + ' x' + i.qty).join('; '), o.subtotal, o.discount, o.shipping, o.total, o.payment, o.paymentStatus, o.status, o.coupon, o.address]));
    sendCsv(res, 'orders.csv', rows);
  });
  app.get('/api/admin/export/products.csv', auth, adminOnly, (req, res) => {
    const rows = [['ID', 'SKU', 'Name', 'Metal', 'Category', 'Purity', 'Weight', 'NetWeightGrams', 'PricingMode', 'MakingType', 'MakingValue', 'StoneCharges', 'Price', 'MRP', 'Stock', 'Sold', 'Rating', 'Active', 'HSN', 'Image', 'Description']];
    db().products.forEach(p => rows.push([p.id, p.sku || '', p.name, p.metal, p.category, p.purity, p.weight, p.netWeightGrams || '', p.pricingMode || 'fixed', p.makingType || 'percent', p.makingValue ?? '', p.stoneCharges || 0, p.price, p.mrp, p.stock, p.sold, p.rating, p.active, p.hsn || '7113', p.image || '', p.description || '']));
    sendCsv(res, 'products.csv', rows);
  });
  app.get('/api/admin/export/customers.csv', auth, adminOnly, (req, res) => {
    const rows = [['Name', 'Email', 'Phone', 'Role', 'Active', 'Joined', 'Orders', 'TotalSpent']];
    db().users.forEach(u => { const os = db().orders.filter(o => o.userId === u.id); rows.push([u.name, u.email, u.phone, u.role, u.active, u.createdAt, os.length, os.filter(o => o.status !== 'Cancelled').reduce((s, o) => s + o.total, 0)]); });
    sendCsv(res, 'customers.csv', rows);
  });

  console.log('🧩 Pro routes registered: /api/config/public, OTP, Google, Razorpay, pricing, upload, shipping/returns, exports, setup-status');
};
