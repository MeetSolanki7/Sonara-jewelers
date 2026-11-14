/* ============================================================
   SONARA JEWELS — Full-Stack E-commerce Server
   Node + Express + JWT + bcrypt + JSON file persistence
   Storefront + Customer Dashboard + Admin Panel APIs
   ============================================================ */
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
/* Tiny .env loader (no extra dependency): KEY=VALUE per line, # = comment */
try {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) fs.readFileSync(envPath, 'utf8').split(/\r?\n/).forEach(line => {
    const m = line.trim().match(/^([^#=]+)=(.*)$/);
    if (m && process.env[m[1].trim()] === undefined) process.env[m[1].trim()] = m[2].trim();
  });
} catch (e) { console.warn('.env load skipped:', e.message); }

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sonara-jewels-secret-change-in-production';
if (JWT_SECRET === 'sonara-jewels-secret-change-in-production') {
  console.warn('⚠️  SECURITY: JWT_SECRET is using the default value! Set a strong JWT_SECRET in .env before going live.');
}
// Production safety checks
const isProd = process.env.NODE_ENV === 'production';
if (isProd) {
  if (String(process.env.OTP_DEV_MODE || 'true') === 'true') console.warn('⚠️  PRODUCTION: OTP_DEV_MODE=true — OTPs are shown on screen! Set OTP_DEV_MODE=false.');
  if (String(process.env.PAYMENTS_TEST_MODE || 'true') === 'true' && !process.env.RAZORPAY_KEY_ID) console.warn('⚠️  PRODUCTION: PAYMENTS_TEST_MODE=true with no Razorpay keys — payments are mocked!');
  if (!process.env.RAZORPAY_KEY_ID) console.warn('⚠️  PRODUCTION: RAZORPAY_KEY_ID not set — online payments disabled (COD only).');
  if (!process.env.MSG91_AUTH_KEY && !process.env.TWILIO_ACCOUNT_SID) console.warn('⚠️  PRODUCTION: No SMS provider configured — OTP login will fail.');
  if (!process.env.GOOGLE_CLIENT_ID) console.warn('⚠️  PRODUCTION: GOOGLE_CLIENT_ID not set — Google login disabled.');
  console.log('🚀 Production mode: all safety checks done.');
}
const DB_PATH = path.join(__dirname, 'data', 'db.json');

/* ================= SECURITY LAYER ================= */
// 1) Security headers (clickjacking, MIME-sniffing, XSS, referrer leaks)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://checkout.razorpay.com https://accounts.google.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://accounts.google.com; frame-src https://checkout.razorpay.com https://accounts.google.com; object-src 'none'; base-uri 'self'; form-action 'self'");
  res.setHeader('X-Powered-By', 'Sonara');
  next();
});
// 2) CORS — same-origin + explicit allow-list only (no wildcard)
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error('CORS blocked'));
  },
  credentials: true,
}));
// 3) Rate limiting (in-memory, per IP) — brute-force / spam protection
const rateBuckets = new Map();
function rateLimit(max, windowMs, label) {
  return (req, res, next) => {
    const ip = (req.headers['x-forwarded-for'] || req.ip || 'unknown').toString().split(',')[0].trim();
    const key = label + ':' + ip;
    const now = Date.now();
    let b = rateBuckets.get(key);
    if (!b || now > b.reset) { b = { count: 0, reset: now + windowMs }; rateBuckets.set(key, b); }
    b.count++;
    if (b.count > max) return res.status(429).json({ error: 'Too many attempts. Please wait a few minutes and try again.' });
    next();
  };
}
setInterval(() => { const now = Date.now(); for (const [k, b] of rateBuckets) if (now > b.reset) rateBuckets.delete(k); }, 60000).unref();
// 4) Input sanitizer — strips HTML/script from all user text (stored-XSS defence in depth)
const cleanStr = (v, max = 500) => String(v ?? '').replace(/<[^>]*>/g, '').replace(/javascript:/gi, '').trim().slice(0, max);

app.use(express.json({ limit: '2mb', verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, filePath){
    // Never serve stale HTML/JS/CSS after a fix (prevents browsers running old code)
    if (/\.(html|js|css)$/i.test(filePath)) res.setHeader('Cache-Control', 'no-store, must-revalidate');
  }
}));

/* ---------------- DB layer (persistent JSON file) ---------------- */
let db;
function saveDB() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  const tmp = DB_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
  try { if (fs.existsSync(DB_PATH)) fs.copyFileSync(DB_PATH, DB_PATH + '.backup'); } catch (e) {}
  fs.renameSync(tmp, DB_PATH); // atomic: never leaves a half-written DB if power fails
}
function loadDB() {
  if (fs.existsSync(DB_PATH)) {
    try { db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); return; }
    catch (e) { console.error('DB parse failed, reseeding', e); }
  }
  db = seed();
  saveDB();
}
const uid = (p='id') => p + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const nowISO = () => new Date().toISOString();
function daysAgo(n, h=10) { const d=new Date(); d.setDate(d.getDate()-n); d.setHours(h,15,0,0); return d.toISOString(); }

/* ---------------- Seed: realistic demo data ---------------- */
function seed() {
  const hash = (pw) => bcrypt.hashSync(pw, 10);

  const categories = [
    { id:'cat_neck', name:'Necklaces & Sets', slug:'necklaces', icon:'📿', description:'Necklace sets, chokers, harams & bridal sets' },
    { id:'cat_ear',  name:'Earrings & Jhumkas', slug:'earrings', icon:'✨', description:'Jhumkas, studs, chandbalis & drops' },
    { id:'cat_bangle', name:'Bangles & Bracelets', slug:'bangles', icon:'⭕', description:'Bangle sets, kadas & bracelets' },
    { id:'cat_ring', name:'Rings', slug:'rings', icon:'💍', description:'Cocktail, band & stone rings' },
    { id:'cat_anklet', name:'Anklets (Payal)', slug:'anklets', icon:'🔔', description:'Silver payals & anklet pairs' },
    { id:'cat_bridal', name:'Bridal Sets', slug:'bridal', icon:'👑', description:'Complete bridal jewellery sets' },
  ];

  const P = (id,name,metal,category,price,mrp,img,extra={}) => Object.assign({
    id, name, metal, category, price, mrp, image: img,
    purity: metal==='Gold' ? '22K BIS Hallmarked' : metal==='Silver' ? '925 Sterling Silver' : 'Premium Gold-Plated (Imitation)',
    weight: '—', rating: 4.5, reviewsCount: 24, sold: 40, stock: 15,
    isFeatured:false, isNew:false, isBestseller:false, active:true,
    description:'', createdAt: daysAgo(40)
  }, extra);

  const products = [
    P('p01','Rajwadi 22K Gold Bridal Necklace Set','Gold','Bridal Sets',285000,320000,'/images/p01.jpg',{weight:'38.4 g',rating:4.9,reviewsCount:132,sold:86,stock:4,isFeatured:true,isBestseller:true,description:'A regal Rajwadi bridal set in 22K BIS-hallmarked gold with intricate nakshi work, matching Jhumka earrings and maang tikka. Handcrafted in Rajkot by master karigars — perfect for weddings and festive trousseaus. BIS Hallmark HUID verified.'}),
    P('p02','Temple 22K Gold Long Haram Set','Gold','Necklaces & Sets',195000,218000,'/images/p02.jpg',{weight:'26.8 g',rating:4.8,reviewsCount:98,sold:64,stock:6,isFeatured:true,isBestseller:true,description:'Traditional South-Indian temple long haram in antique-finish 22K gold, inspired by Laxmi coin & peacock motifs. Pairs beautifully with silk sarees for weddings and poojas.'}),
    P('p03','Antique Gold Jhumka & Bangle Box Set (22K)','Gold','Bangles & Bracelets',128500,145000,'/images/p03.jpg',{weight:'18.2 g',rating:4.7,reviewsCount:76,sold:52,stock:8,isFeatured:true,description:'Festive box set with 4 gold bangles and classic bell jhumkas in 22K gold. BIS hallmarked, with lifetime exchange and transparent buy-back.'}),
    P('p04','Polki Pearl Gold Bangle Set — 22K','Gold','Bangles & Bracelets',86999,98500,'/images/p04.jpg',{weight:'12.6 g',rating:4.6,reviewsCount:54,sold:41,stock:11,isNew:true,description:'Elegant polki-style bangles with pearl drops in 22K gold. Lightweight yet rich — ideal for sangeet, engagement and festive wear.'}),
    P('p05','American Diamond Gold Bangles — 18K (Pair)','Gold','Bangles & Bracelets',64500,74000,'/images/p05.jpg',{purity:'18K BIS Hallmarked',weight:'9.4 g',rating:4.5,reviewsCount:47,sold:38,stock:14,description:'Sparkling American diamonds set in 18K gold bangles (pair of 2). Secure screw-lock, everyday-luxe shine that goes from office to occasion.'}),
    P('p06','Classic 22K Gold Choker + Jhumka Set','Gold','Necklaces & Sets',112000,126000,'/images/p06.jpg',{weight:'15.9 g',rating:4.8,reviewsCount:89,sold:57,stock:5,isBestseller:true,description:'Timeless gold choker with floral etching and matching jhumkas in 22K hallmarked gold. A versatile heirloom for weddings and festivals.'}),

    P('p07','925 Silver Oxidized Anklets (Payal) — Pair','Silver','Anklets (Payal)',2499,3999,'/images/p07.jpg',{weight:'28 g',rating:4.7,reviewsCount:211,sold:340,stock:42,isFeatured:true,isBestseller:true,description:'Handcrafted 925 sterling silver payal pair with oxidized finish and tiny ghungroo bells. Skin-friendly, tarnish-resistant polish. Length 10.5 inch, adjustable.'}),
    P('p08','Oxidized Silver Hasli & Anklet Combo','Silver','Necklaces & Sets',3299,4999,'/images/p08.webp',{weight:'46 g',rating:4.4,reviewsCount:88,sold:129,stock:23,isNew:true,description:'Statement oxidized hasli choker with matching anklet — a boho-ethnic combo loved for Navratri garba, kurtis and sarees. German-silver base with silver plating.'}),
    P('p09','Ghungroo Silver Anklet Pair — 925','Silver','Anklets (Payal)',1899,2999,'/images/p09.jpg',{weight:'22 g',rating:4.6,reviewsCount:167,sold:258,stock:3,description:'Classic ghungroo payal in 925 silver with a soft, musical chime. Daily-wear friendly with sturdy S-hook clasp.'}),
    P('p10','Traditional Silver Payal with Charms','Silver','Anklets (Payal)',2199,3499,'/images/p10.jpg',{weight:'25 g',rating:4.5,reviewsCount:94,sold:141,stock:31,description:'Charm-detailed traditional payal in sterling silver — bridal-trousseau favourite and a thoughtful gift for new brides.'}),
    P('p11','Oxidized Mirror Choker Necklace Set','Silver','Necklaces & Sets',2999,4499,'/images/p11.jpg',{weight:'58 g',rating:4.6,reviewsCount:73,sold:98,stock:18,isFeatured:true,description:'Tribal mirror-work choker set with oxidized silver finish and matching earrings. The Navratri & festive bestseller — pairs with chaniya choli and Indo-western looks.'}),

    P('p12','Kundan Polki Mirror Choker Set (Imitation)','Imitation','Necklaces & Sets',2499,5999,'/images/p12.jpg',{weight:'—',rating:4.5,reviewsCount:188,sold:412,stock:56,isFeatured:true,isBestseller:true,description:'Premium Kundan polki choker with mirror detailing, gold-plated finish and matching earrings. Bridal look at an imitation price — lightweight and skin-friendly.'}),
    P('p13','Gold-Plated Kundan Ruby-Emerald Set','Imitation','Bridal Sets',3499,7999,'/images/p13.jpg',{rating:4.6,reviewsCount:143,sold:287,stock:34,isBestseller:true,description:'Rich ruby-emerald Kundan set with gold plating, necklace + earrings + maang tikka. Wedding-guest and sangeet favourite. Comes in a gift-ready box.'}),
    P('p14','Temple Imitation Necklace Set — Laxmi Haram','Imitation','Necklaces & Sets',1999,4499,'/images/p14.jpg',{rating:4.4,reviewsCount:116,sold:230,stock:47,description:'South-Indian temple-style Laxmi haram with Kemp stones, matte gold finish. Get the heirloom temple look without the gold price.'}),
    P('p15','Bridal Kundan Choker Set with Tikka','Imitation','Bridal Sets',3999,8999,'/images/p15.jpg',{rating:4.7,reviewsCount:204,sold:365,stock:28,isFeatured:true,description:'Complete bridal Kundan choker set — choker, long necklace, earrings, maang tikka & nath. Hand-set stones, adjustable dori, premium polish warranty of 6 months.'}),
    P('p16','Moissanite Kundan Necklace Set','Imitation','Necklaces & Sets',4299,9999,'/images/p16.png',{rating:4.8,reviewsCount:91,sold:154,stock:19,isNew:true,description:'Dazzling moissanite-look Kundan set with gold plating. Diamond-like fire, feather-light comfort — made for receptions and cocktail evenings.'}),
    P('p17','Rhinestone Wedding Jewellery Set','Imitation','Bridal Sets',1499,3999,'/images/p17.jpg',{rating:4.2,reviewsCount:67,sold:198,stock:2,description:'Crystal rhinestone necklace, earrings & bracelet set — a budget-friendly sparkle for parties, farewells and festive evenings.'}),
    P('p18','Kundan Gold-Chain Choker + Jhumka Set','Imitation','Necklaces & Sets',2799,6499,'/images/p18.jpg',{rating:4.5,reviewsCount:128,sold:241,stock:39,isNew:true,description:'Gold-chain choker with Kundan drops and classic jhumkas, oxidized-gold dual tone. A versatile festive set for sarees and lehengas.'}),
    P('p19','Bright Gold Bangle & Jhumka Set (Imitation)','Imitation','Bangles & Bracelets',1799,4499,'/images/p19.jpg',{rating:4.4,reviewsCount:152,sold:390,stock:64,description:'Box set of bright gold-finish bangles with matching jhumkas. Mix, match and stack — sizes 2.4 / 2.6 / 2.8 available.'}),
    P('p20','Antique Crystal Pearl Bangles — Set of 6','Imitation','Bangles & Bracelets',1299,2999,'/images/p20.jpg',{rating:4.3,reviewsCount:84,sold:213,stock:0,description:'Antique gold-tone crystal bangles with pearl hangings (set of 6). Ethnic bridal charm for mehendi and haldi looks.'}),
  ];

  const users = [
    { id:'u_admin', name:'Admin — Sonara Jewels', email:'admin@sonara.in', phone:'9876543210', password:hash('admin123'), role:'admin', active:true, createdAt:daysAgo(180) },
    { id:'u_priya', name:'Priya Sharma', email:'priya@example.com', phone:'9825012345', password:hash('customer123'), role:'customer', active:true, createdAt:daysAgo(120) },
    { id:'u_anjali', name:'Anjali Patel', email:'anjali.patel@gmail.com', phone:'9898123456', password:hash('customer123'), role:'customer', active:true, createdAt:daysAgo(95) },
    { id:'u_meera', name:'Meera Desai', email:'meera.desai@yahoo.in', phone:'9426034567', password:hash('customer123'), role:'customer', active:true, createdAt:daysAgo(70) },
    { id:'u_sneha', name:'Sneha Reddy', email:'sneha.reddy@gmail.com', phone:'9908045678', password:hash('customer123'), role:'customer', active:true, createdAt:daysAgo(52) },
    { id:'u_kavita', name:'Kavita Rao', email:'Kavita Rao@gmail.com', phone:'9845056789', password:hash('customer123'), role:'customer', active:true, createdAt:daysAgo(33) },
    { id:'u_ritu', name:'Rajesh Verma', email:'Rajesh Verma@gmail.com', phone:'9717067890', password:hash('customer123'), role:'customer', active:true, createdAt:daysAgo(18) },
  ];

  const addresses = [
    { id:'addr_1', userId:'u_priya', label:'Home', name:'Priya Sharma', phone:'9825012345', line1:'B-12, Shivalaya Heights, Kalavad Road', city:'Rajkot', state:'Gujarat', pincode:'360005', isDefault:true },
    { id:'addr_2', userId:'u_priya', label:'Office', name:'Priya Sharma', phone:'9825012345', line1:'3rd Floor, Crystal Mall Business Hub', city:'Rajkot', state:'Gujarat', pincode:'360001', isDefault:false },
    { id:'addr_3', userId:'u_anjali', label:'Home', name:'Anjali Patel', phone:'9898123456', line1:'45, Sardar Patel Nagar, Race Course Road', city:'Ahmedabad', state:'Gujarat', pincode:'380015', isDefault:true },
    { id:'addr_4', userId:'u_meera', label:'Home', name:'Meera Desai', phone:'9426034567', line1:'9, Alkapuri Society, RC Dutt Road', city:'Vadodara', state:'Gujarat', pincode:'390007', isDefault:true },
  ];

  const byId = Object.fromEntries(products.map(p=>[p.id,p]));
  const item = (pid, qty=1) => ({ productId:pid, name:byId[pid].name, image:byId[pid].image, price:byId[pid].price, qty });
  const total = (items, ship=0, disc=0) => items.reduce((s,i)=>s+i.price*i.qty,0) + ship - disc;

  const orders = [
    { id:'SON1001', userId:'u_priya', customerName:'Priya Sharma', email:'priya@example.com', phone:'9825012345', items:[item('p12',1),item('p07',1)], subtotal:4998, discount:500, shipping:0, total:4498, coupon:'WELCOME10', payment:'UPI', paymentStatus:'Paid', status:'Delivered', address:'B-12, Shivalaya Heights, Kalavad Road, Rajkot — 360005', createdAt:daysAgo(22), timeline:[{s:'Placed',t:daysAgo(22)},{s:'Processing',t:daysAgo(21)},{s:'Shipped',t:daysAgo(20)},{s:'Delivered',t:daysAgo(18)}] },
    { id:'SON1002', userId:'u_anjali', customerName:'Anjali Patel', email:'anjali.patel@gmail.com', phone:'9898123456', items:[item('p01',1)], subtotal:285000, discount:14250, shipping:0, total:270750, coupon:'GOLD5', payment:'Card', paymentStatus:'Paid', status:'Delivered', address:'45, Sardar Patel Nagar, Race Course Road, Ahmedabad — 380015', createdAt:daysAgo(19), timeline:[{s:'Placed',t:daysAgo(19)},{s:'Processing',t:daysAgo(18)},{s:'Shipped',t:daysAgo(16)},{s:'Delivered',t:daysAgo(14)}] },
    { id:'SON1003', userId:'u_meera', customerName:'Meera Desai', email:'meera.desai@yahoo.in', phone:'9426034567', items:[item('p15',1),item('p19',2)], subtotal:7597, discount:0, shipping:0, total:7597, coupon:'', payment:'COD', paymentStatus:'Pending (COD)', status:'Shipped', address:'9, Alkapuri Society, RC Dutt Road, Vadodara — 390007', createdAt:daysAgo(6), timeline:[{s:'Placed',t:daysAgo(6)},{s:'Processing',t:daysAgo(5)},{s:'Shipped',t:daysAgo(3)}] },
    { id:'SON1004', userId:'u_priya', customerName:'Priya Sharma', email:'priya@example.com', phone:'9825012345', items:[item('p11',1)], subtotal:2999, discount:450, shipping:0, total:2549, coupon:'SILVER15', payment:'UPI', paymentStatus:'Paid', status:'Delivered', address:'B-12, Shivalaya Heights, Kalavad Road, Rajkot — 360005', createdAt:daysAgo(12), timeline:[{s:'Placed',t:daysAgo(12)},{s:'Processing',t:daysAgo(11)},{s:'Shipped',t:daysAgo(10)},{s:'Delivered',t:daysAgo(8)}] },
    { id:'SON1005', userId:'u_sneha', customerName:'Sneha Reddy', email:'sneha.reddy@gmail.com', phone:'9908045678', items:[item('p06',1)], subtotal:112000, discount:0, shipping:0, total:112000, coupon:'', payment:'Net Banking', paymentStatus:'Paid', status:'Processing', address:'Plot 88, Jubilee Hills, Hyderabad — 500033', createdAt:daysAgo(2), timeline:[{s:'Placed',t:daysAgo(2)},{s:'Processing',t:daysAgo(1)}] },
    { id:'SON1006', userId:'u_kavita', customerName:'Kavita Rao', email:'Kavita Rao@gmail.com', phone:'9845056789', items:[item('p07',2),item('p09',1)], subtotal:6897, discount:0, shipping:0, total:6897, coupon:'', payment:'UPI', paymentStatus:'Paid', status:'Shipped', address:'17, 4th Cross, Jayanagar, Bengaluru — 560041', createdAt:daysAgo(4), timeline:[{s:'Placed',t:daysAgo(4)},{s:'Processing',t:daysAgo(3)},{s:'Shipped',t:daysAgo(2)}] },
    { id:'SON1007', userId:'u_ritu', customerName:'Rajesh Verma', email:'Rajesh Verma@gmail.com', phone:'9717067890', items:[item('p16',1)], subtotal:4299, discount:0, shipping:0, total:4299, coupon:'', payment:'Card', paymentStatus:'Paid', status:'Pending', address:'H-42, Lajpat Nagar II, New Delhi — 110024', createdAt:daysAgo(1), timeline:[{s:'Placed',t:daysAgo(1)}] },
    { id:'SON1008', userId:'u_priya', customerName:'Priya Sharma', email:'priya@example.com', phone:'9825012345', items:[item('p18',1)], subtotal:2799, discount:0, shipping:0, total:2799, coupon:'', payment:'COD', paymentStatus:'Pending (COD)', status:'Pending', address:'B-12, Shivalaya Heights, Kalavad Road, Rajkot — 360005', createdAt:daysAgo(0,11), timeline:[{s:'Placed',t:daysAgo(0,11)}] },
    { id:'SON1009', userId:'u_meera', customerName:'Meera Desai', email:'meera.desai@yahoo.in', phone:'9426034567', items:[item('p03',1)], subtotal:128500, discount:6425, shipping:0, total:122075, coupon:'GOLD5', payment:'Card', paymentStatus:'Paid', status:'Delivered', address:'9, Alkapuri Society, RC Dutt Road, Vadodara — 390007', createdAt:daysAgo(16), timeline:[{s:'Placed',t:daysAgo(16)},{s:'Processing',t:daysAgo(15)},{s:'Shipped',t:daysAgo(13)},{s:'Delivered',t:daysAgo(11)}] },
    { id:'SON1010', userId:'u_anjali', customerName:'Anjali Patel', email:'anjali.patel@gmail.com', phone:'9898123456', items:[item('p13',1),item('p20',1)], subtotal:4798, discount:960, shipping:0, total:3838, coupon:'FESTIVE20', payment:'UPI', paymentStatus:'Paid', status:'Cancelled', address:'45, Sardar Patel Nagar, Ahmedabad — 380015', createdAt:daysAgo(9), timeline:[{s:'Placed',t:daysAgo(9)},{s:'Cancelled',t:daysAgo(8)}] },
    { id:'SON1011', userId:'u_sneha', customerName:'Sneha Reddy', email:'sneha.reddy@gmail.com', phone:'9908045678', items:[item('p14',1),item('p10',1)], subtotal:4198, discount:0, shipping:0, total:4198, coupon:'', payment:'UPI', paymentStatus:'Paid', status:'Delivered', address:'Plot 88, Jubilee Hills, Hyderabad — 500033', createdAt:daysAgo(15), timeline:[{s:'Placed',t:daysAgo(15)},{s:'Processing',t:daysAgo(14)},{s:'Shipped',t:daysAgo(13)},{s:'Delivered',t:daysAgo(11)}] },
    { id:'SON1012', userId:'u_kavita', customerName:'Kavita Rao', email:'Kavita Rao@gmail.com', phone:'9845056789', items:[item('p05',1)], subtotal:64500, discount:0, shipping:0, total:64500, coupon:'', payment:'Card', paymentStatus:'Paid', status:'Processing', address:'17, 4th Cross, Jayanagar, Bengaluru — 560041', createdAt:daysAgo(3), timeline:[{s:'Placed',t:daysAgo(3)},{s:'Processing',t:daysAgo(2)}] },
    { id:'SON1013', userId:'u_ritu', customerName:'Rajesh Verma', email:'Rajesh Verma@gmail.com', phone:'9717067890', items:[item('p08',1),item('p17',1)], subtotal:4798, discount:0, shipping:0, total:4798, coupon:'', payment:'COD', paymentStatus:'Pending (COD)', status:'Delivered', address:'H-42, Lajpat Nagar II, New Delhi — 110024', createdAt:daysAgo(11), timeline:[{s:'Placed',t:daysAgo(11)},{s:'Processing',t:daysAgo(10)},{s:'Shipped',t:daysAgo(9)},{s:'Delivered',t:daysAgo(7)}] },
    { id:'SON1014', userId:'u_priya', customerName:'Priya Sharma', email:'priya@example.com', phone:'9825012345', items:[item('p04',1)], subtotal:86999, discount:0, shipping:0, total:86999, coupon:'', payment:'UPI', paymentStatus:'Paid', status:'Shipped', address:'B-12, Shivalaya Heights, Kalavad Road, Rajkot — 360005', createdAt:daysAgo(5), timeline:[{s:'Placed',t:daysAgo(5)},{s:'Processing',t:daysAgo(4)},{s:'Shipped',t:daysAgo(2)}] },
  ];

  const coupons = [
    { id:'cp1', code:'WELCOME10', type:'percent', value:10, minOrder:999, maxDiscount:2000, expires:'2026-12-31', active:true, used:48 },
    { id:'cp2', code:'GOLD5', type:'percent', value:5, minOrder:25000, maxDiscount:15000, expires:'2026-12-31', active:true, used:21 },
    { id:'cp3', code:'FESTIVE20', type:'percent', value:20, minOrder:1999, maxDiscount:3000, expires:'2026-11-30', active:true, used:73 },
    { id:'cp4', code:'SILVER15', type:'percent', value:15, minOrder:1499, maxDiscount:1500, expires:'2026-12-31', active:true, used:35 },
    { id:'cp5', code:'FLAT500', type:'flat', value:500, minOrder:2999, maxDiscount:500, expires:'2026-10-31', active:false, used:12 },
  ];

  const reviews = [
    { id:'r1', productId:'p01', userName:'Anjali Patel', rating:5, text:'Bought this for my wedding — the nakshi work is stunning and BIS hallmark gave full confidence. Got compliments all evening!', createdAt:daysAgo(13) },
    { id:'r2', productId:'p01', userName:'Meera Desai', rating:5, text:'Heavy, rich and exactly like the photos. Delivery to Vadodara in 4 days with insured packaging.', createdAt:daysAgo(9) },
    { id:'r3', productId:'p07', userName:'Priya Sharma', rating:5, text:'Wearing these payals daily for 3 weeks — no tarnish, sweet ghungroo sound. Perfect 925 quality.', createdAt:daysAgo(17) },
    { id:'r4', productId:'p12', userName:'Sneha Reddy', rating:4, text:'Looks like real Kundan! Lightweight for long functions. Took one star off as dori could be longer.', createdAt:daysAgo(10) },
    { id:'r5', productId:'p15', userName:'Kavita Rao', rating:5, text:'Complete bridal set at this price is unbelievable. Photos came out gorgeous.', createdAt:daysAgo(6) },
    { id:'r6', productId:'p11', userName:'Priya Sharma', rating:5, text:'Navratri star! Mirror choker with chaniya choli = so many compliments. Must buy.', createdAt:daysAgo(7) },
    { id:'r7', productId:'p06', userName:'Rajesh Verma', rating:5, text:'Gifted to my mother. Hallmark verified on BIS app, elegant choker, very happy with making quality.', createdAt:daysAgo(20) },
    { id:'r8', productId:'p16', userName:'Anjali Patel', rating:5, text:'Moissanite sparkle is unreal — everyone thought it was diamonds. Reception ready!', createdAt:daysAgo(4) },
  ];

  return {
    users, products, categories, orders, coupons, reviews, addresses,
    carts: { 'u_priya': [{productId:'p13', qty:1}] },
    wishlists: { 'u_priya': ['p02','p16','p07'] },
    settings: {
      storeName:'Sonara Jewels', tagline:'Gold • Silver • Imitation — for every celebration',
      gold22k: 8945, gold24k: 9760, silver: 112,
      freeShipAbove: 999, shippingFee: 79,
      announcement:'✨ Festive Sale — Up to 55% OFF on Imitation • Extra 5% OFF on Gold with GOLD5 • Free insured shipping over ₹999',
      supportEmail:'care@sonara.in', supportPhone:'+91 98765 43210',
      address:'Sonara Jewels, Palace Road, Rajkot, Gujarat — 360001'
    },
    orderSeq: 1015
  };
}

/* ---------------- Auth helpers ---------------- */
function publicUser(u){ return { id:u.id, name:u.name, email:u.email, phone:u.phone, role:u.role, active:u.active, createdAt:u.createdAt }; }
function sign(u){ return jwt.sign({ id:u.id, role:u.role, email:u.email }, JWT_SECRET, { expiresIn:'7d' }); }
function auth(req,res,next){
  const bearer = (req.headers.authorization||'').startsWith('Bearer ') ? req.headers.authorization.slice(7) : null;
  let cookieTok = null;
  const cm = /(?:^|;\s*)sonara_token=([^;]+)/.exec(req.headers.cookie||'');
  if(cm){ try{ cookieTok = decodeURIComponent(cm[1]); }catch(e){ cookieTok = cm[1]; } }
  // Some preview/proxy layers strip or replace the Authorization header.
  // Accept the same JWT via a dedicated header or cookie too, so logins survive those layers.
  const candidates = [...new Set([req.headers['x-auth-token'], bearer, cookieTok].map(t => (t==null?'':String(t)).trim()).filter(Boolean))];
  if(!candidates.length) return res.status(401).json({ error:'Please login to continue' });
  let sawVerified = false;
  for(const token of candidates){
    try{
      const dec = jwt.verify(token, JWT_SECRET);
      const user = db.users.find(u=>u.id===dec.id);
      if(user && user.active){ req.user = user; return next(); }
      sawVerified = true; // token genuine, but account missing/blocked
    }catch(e){ /* try next delivery route */ }
  }
  if(sawVerified) return res.status(401).json({ error:'Account not found or blocked. Please contact support.' });
  return res.status(401).json({ error:'Session expired. Please login again' });
}
function adminOnly(req,res,next){
  if(req.user.role==='admin') return next();
  if(req.user.role==='staff'){
    const p = req.path, m = req.method;
    const staffOk =
      (p.startsWith('/api/products') && m!=='DELETE') ||
      p.startsWith('/api/admin/products') ||
      p.startsWith('/api/orders') ||
      p==='/api/stats/admin' ||
      (p.startsWith('/api/categories') && m==='GET');
    if(staffOk) return next();
  }
  return res.status(403).json({ error:'Admin access required' });
}
const normPhone = (p='') => String(p).replace(/\D/g,'').replace(/^91(\d{10})$/,'$1');

/* ---------------- Auth routes (Email OR Phone login) ---------------- */
// Account lockout: 5 failed logins → locked for 15 minutes (per account)
const loginFails = new Map(); // userId -> {count, lockedUntil}
function isLocked(userId) {
  const f = loginFails.get(userId);
  if (!f) return false;
  if (f.lockedUntil && Date.now() < f.lockedUntil) return true;
  if (f.lockedUntil) loginFails.delete(userId);
  return false;
}
function recordFail(userId) {
  const f = loginFails.get(userId) || { count: 0 };
  f.count++;
  if (f.count >= 5) f.lockedUntil = Date.now() + 15 * 60 * 1000;
  loginFails.set(userId, f);
}
const strongPassword = (pw) => String(pw || '').length >= 8 && /[a-zA-Z]/.test(pw) && /\d/.test(pw);

app.post('/api/auth/register', rateLimit(8, 10 * 60 * 1000, 'register'), (req,res)=>{
  const { name, email, phone, password } = req.body||{};
  if(!name || !email || !phone || !password) return res.status(400).json({ error:'Name, email, phone and password are required' });
  if(!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error:'Please enter a valid email address' });
  const ph = normPhone(phone);
  if(ph.length!==10) return res.status(400).json({ error:'Please enter a valid 10-digit mobile number' });
  if(!strongPassword(password)) return res.status(400).json({ error:'Password must be at least 8 characters with letters and numbers' });
  if(db.users.some(u=>u.email.toLowerCase()===email.toLowerCase())) return res.status(409).json({ error:'This email is already registered. Please login.' });
  if(db.users.some(u=>normPhone(u.phone)===ph)) return res.status(409).json({ error:'This mobile number is already registered. Please login.' });
  const user = { id:uid('u'), name:cleanStr(name, 80), email:email.toLowerCase(), phone:ph, password:bcrypt.hashSync(password,10), role:'customer', active:true, createdAt:nowISO() };
  db.users.push(user); saveDB();
  res.status(201).json({ token:sign(user), user:publicUser(user) });
});

app.post('/api/auth/login', rateLimit(20, 5 * 60 * 1000, 'login'), (req,res)=>{
  const { identifier, password } = req.body||{};
  if(!identifier || !password) return res.status(400).json({ error:'Enter your email or mobile number and password' });
  const idf = String(identifier).trim();
  const user = db.users.find(u => u.email.toLowerCase()===idf.toLowerCase() || normPhone(u.phone)===normPhone(idf));
  // Generic error — never reveal whether the account exists (user-enumeration defence)
  if(!user || !bcrypt.compareSync(password, user.password)) {
    if (user) recordFail(user.id);
    return res.status(401).json({ error:'Invalid email / mobile number or password. Please try again.' });
  }
  if(!user.active) return res.status(403).json({ error:'Your account has been blocked. Please contact support.' });
  if(isLocked(user.id)) return res.status(423).json({ error:'Account temporarily locked due to too many failed attempts. Try again in 15 minutes.' });
  loginFails.delete(user.id);
  res.json({ token:sign(user), user:publicUser(user) });
});

app.get('/api/auth/me', auth, (req,res)=> res.json({ user:publicUser(req.user) }));

app.put('/api/auth/profile', auth, (req,res)=>{
  const { name, email, phone, currentPassword, newPassword } = req.body||{};
  const u = req.user;
  if(name) u.name = cleanStr(name, 80);
  if(email && email.toLowerCase()!==u.email.toLowerCase()){
    if(db.users.some(x=>x.id!==u.id && x.email.toLowerCase()===email.toLowerCase())) return res.status(409).json({ error:'Email already in use' });
    u.email = email.toLowerCase();
  }
  if(phone){
    const ph = normPhone(phone);
    if(ph.length!==10) return res.status(400).json({ error:'Enter a valid 10-digit mobile number' });
    if(db.users.some(x=>x.id!==u.id && normPhone(x.phone)===ph)) return res.status(409).json({ error:'Mobile number already in use' });
    u.phone = ph;
  }
  if(newPassword){
    if(!currentPassword || !bcrypt.compareSync(currentPassword, u.password)) return res.status(400).json({ error:'Current password is incorrect' });
    if(!strongPassword(newPassword)) return res.status(400).json({ error:'New password must be at least 8 characters with letters and numbers' });
    u.password = bcrypt.hashSync(newPassword,10);
  }
  saveDB(); res.json({ user:publicUser(u) });
});

/* ---------------- Settings / public ---------------- */
app.get('/api/settings', (req,res)=> res.json(db.settings));
app.put('/api/settings', auth, adminOnly, (req,res)=>{
  db.settings = Object.assign({}, db.settings, req.body||{});
  saveDB(); res.json(db.settings);
});
app.get('/api/health', (req,res)=> res.json({ ok:true, store:db.settings.storeName, products:db.products.length, orders:db.orders.length }));

/* ---------------- Categories CRUD ---------------- */
app.get('/api/categories', (req,res)=>{
  const list = db.categories.map(c=>({ ...c, productCount: db.products.filter(p=>p.category===c.name && p.active).length }));
  res.json(list);
});
app.post('/api/categories', auth, adminOnly, (req,res)=>{
  const { name, icon, description } = req.body||{};
  if(!name) return res.status(400).json({ error:'Category name is required' });
  if(db.categories.some(c=>c.name.toLowerCase()===name.toLowerCase())) return res.status(409).json({ error:'Category already exists' });
  const cat = { id:uid('cat'), name, slug:name.toLowerCase().replace(/\s+/g,'-'), icon:icon||'💎', description:description||'' };
  db.categories.push(cat); saveDB(); res.status(201).json(cat);
});
app.put('/api/categories/:id', auth, adminOnly, (req,res)=>{
  const cat = db.categories.find(c=>c.id===req.params.id);
  if(!cat) return res.status(404).json({ error:'Category not found' });
  const old = cat.name;
  Object.assign(cat, { name:req.body.name||cat.name, icon:req.body.icon||cat.icon, description:req.body.description??cat.description });
  if(old!==cat.name) db.products.forEach(p=>{ if(p.category===old) p.category=cat.name; });
  saveDB(); res.json(cat);
});
app.delete('/api/categories/:id', auth, adminOnly, (req,res)=>{
  const i = db.categories.findIndex(c=>c.id===req.params.id);
  if(i<0) return res.status(404).json({ error:'Category not found' });
  const [removed] = db.categories.splice(i,1); saveDB(); res.json({ deleted:removed.id });
});

/* ---------------- Products CRUD + search/filter ---------------- */
app.get('/api/products', (req,res)=>{
  const { q='', metal='', category='', min='', max='', sort='popular', featured='', inStock='' } = req.query;
  let list = db.products.filter(p=>p.active && !p.archived);
  if(req.query.admin==='1'){ /* handled separately below, still public-safe */ }
  if(q){ const s=q.toLowerCase(); list=list.filter(p=>(p.name+' '+p.metal+' '+p.category+' '+p.description).toLowerCase().includes(s)); }
  if(metal) list=list.filter(p=>p.metal===metal);
  if(category) list=list.filter(p=>p.category===category);
  if(min!=='') list=list.filter(p=>p.price>=+min);
  if(max!=='') list=list.filter(p=>p.price<=+max);
  if(featured==='1') list=list.filter(p=>p.isFeatured);
  if(inStock==='1') list=list.filter(p=>p.stock>0);
  const sorters = {
    popular:(a,b)=>b.sold-a.sold, newest:(a,b)=>new Date(b.createdAt)-new Date(a.createdAt),
    'price-low':(a,b)=>a.price-b.price, 'price-high':(a,b)=>b.price-a.price,
    rating:(a,b)=>b.rating-a.rating, discount:(a,b)=>((b.mrp-b.price)/b.mrp)-((a.mrp-a.price)/a.mrp)
  };
  list.sort(sorters[sort]||sorters.popular);
  res.json(list);
});
app.get('/api/admin/products', auth, adminOnly, (req,res)=> res.json(db.products));
app.get('/api/products/:id', (req,res)=>{
  const p = db.products.find(x=>x.id===req.params.id);
  if(!p) return res.status(404).json({ error:'Product not found' });
  res.json(p);
});
const METALS = ['Gold','Silver','Imitation'];
function skuTaken(sku, exceptId){ if(!sku) return false; const s=String(sku).trim().toLowerCase(); return db.products.some(p=>p.id!==exceptId && String(p.sku||'').toLowerCase()===s); }
function cleanImages(val, fallback){ return Array.isArray(val) ? val.map(x=>String(x).trim()).filter(Boolean).slice(0,8) : (fallback||[]); }
app.post('/api/products', auth, adminOnly, (req,res)=>{
  const b = req.body||{};
  const name = String(b.name||'').trim();
  if(name.length<3) return res.status(400).json({ error:'Product name is required (min 3 characters)' });
  if(!METALS.includes(b.metal)) return res.status(400).json({ error:'Metal must be Gold, Silver or Imitation' });
  if(!String(b.category||'').trim()) return res.status(400).json({ error:'Category is required' });
  const price = Math.round(+b.price||0);
  if(!(price>0)) return res.status(400).json({ error:'Selling price must be more than 0' });
  let mrp = Math.round(+(b.mrp||price)); if(mrp<price) mrp=price;
  const stock = Math.max(0, parseInt(b.stock??10,10)||0);
  let sku = String(b.sku||'').trim();
  if(sku && skuTaken(sku)) return res.status(400).json({ error:'SKU "'+sku+'" is already used by another product' });
  const id = uid('p'); if(!sku) sku = 'SKU-'+id.replace(/[^a-z0-9]/gi,'').toUpperCase();
  const p = {
    id, name, metal:b.metal, category:String(b.category).trim(),
    price, mrp, image:b.image||'/images/p12.jpg', images:cleanImages(b.images),
    purity:b.purity||(b.metal==='Gold'?'22K BIS Hallmarked':b.metal==='Silver'?'925 Sterling Silver':'Premium Gold-Plated (Imitation)'),
    weight:b.weight||'—', rating:Math.min(5,Math.max(0,+(b.rating||4.5))), reviewsCount:0, sold:0, stock,
    isFeatured:!!b.isFeatured, isNew:!!b.isNew, isBestseller:!!b.isBestseller, active:b.active!==false, archived:false,
    description:String(b.description||''), sku, hsn:String(b.hsn||'7113'),
    pricingMode:b.pricingMode==='weight'?'weight':'fixed', netWeightGrams:+b.netWeightGrams||0,
    makingType:['percent','perGram','flat'].includes(b.makingType)?b.makingType:'percent', makingValue:+b.makingValue||0, stoneCharges:+b.stoneCharges||0,
    createdAt:nowISO()
  };
  db.products.unshift(p); saveDB(); res.status(201).json(p);
});
app.put('/api/products/:id', auth, adminOnly, (req,res)=>{
  const p = db.products.find(x=>x.id===req.params.id);
  if(!p) return res.status(404).json({ error:'Product not found' });
  const b=req.body||{};
  if(b.name!=null){ const n=String(b.name).trim(); if(n.length<3) return res.status(400).json({ error:'Product name is required (min 3 characters)' }); p.name=n; }
  if(b.metal!=null){ if(!METALS.includes(b.metal)) return res.status(400).json({ error:'Metal must be Gold, Silver or Imitation' }); p.metal=b.metal; }
  if(b.category!=null){ const c=String(b.category).trim(); if(!c) return res.status(400).json({ error:'Category is required' }); p.category=c; }
  ['image','purity','weight','description','hsn'].forEach(k=>{ if(b[k]!=null) p[k]= typeof b[k]==='string' ? b[k].trim() : b[k]; });
  if(b.images!=null) p.images = cleanImages(b.images, p.images);
  if(b.sku!=null){ const s=String(b.sku).trim(); if(s && skuTaken(s,p.id)) return res.status(400).json({ error:'SKU "'+s+'" is already used by another product' }); if(s) p.sku=s; }
  if(b.price!=null){ const pr=Math.round(+b.price||0); if(!(pr>0)) return res.status(400).json({ error:'Selling price must be more than 0' }); p.price=pr; }
  if(b.mrp!=null) p.mrp=Math.round(+b.mrp||0);
  if(p.mrp<p.price) p.mrp=p.price;
  if(b.stock!=null) p.stock=Math.max(0, parseInt(b.stock,10)||0);
  if(b.rating!=null) p.rating=Math.min(5,Math.max(0,+b.rating||0));
  ['isFeatured','isNew','isBestseller','active','archived'].forEach(k=>{ if(b[k]!=null) p[k]=!!b[k]; });
  if(b.pricingMode) p.pricingMode = b.pricingMode==='weight'?'weight':'fixed';
  if(b.netWeightGrams!=null) p.netWeightGrams=+b.netWeightGrams||0;
  if(b.makingType && ['percent','perGram','flat'].includes(b.makingType)) p.makingType=b.makingType;
  if(b.makingValue!=null) p.makingValue=+b.makingValue||0;
  if(b.stoneCharges!=null) p.stoneCharges=+b.stoneCharges||0;
  p.updatedAt = nowISO();
  saveDB(); res.json(p);
});
app.post('/api/products/:id/duplicate', auth, adminOnly, (req,res)=>{
  const src = db.products.find(x=>x.id===req.params.id);
  if(!src) return res.status(404).json({ error:'Product not found' });
  let sku = (src.sku||'SKU')+'-COPY'; let n=2;
  while(skuTaken(sku)){ sku=(src.sku||'SKU')+'-COPY'+n; n++; }
  const copy = { ...src, id:uid('p'), name:src.name+' (Copy)', sku, sold:0, reviewsCount:0, active:false, archived:false, createdAt:nowISO(), updatedAt:nowISO() };
  copy.images = [...(src.images||[])];
  if(copy.priceBreakup) copy.priceBreakup = { ...copy.priceBreakup };
  db.products.unshift(copy); saveDB(); res.status(201).json(copy);
});
app.delete('/api/products/:id', auth, adminOnly, (req,res)=>{
  const i = db.products.findIndex(x=>x.id===req.params.id);
  if(i<0) return res.status(404).json({ error:'Product not found' });
  const p = db.products[i];
  const cleanup = ()=>{ Object.keys(db.wishlists).forEach(k=> db.wishlists[k]=db.wishlists[k].filter(x=>x!==p.id)); Object.keys(db.carts).forEach(k=> db.carts[k]=db.carts[k].filter(x=>x.productId!==p.id)); };
  const usedInOrders = (db.orders||[]).some(o=>(o.items||[]).some(it=>it.productId===p.id));
  if(usedInOrders){
    // Never destroy order history — archive (hide) instead of hard-delete
    p.active=false; p.archived=true; p.updatedAt=nowISO(); cleanup(); saveDB();
    return res.json({ archived:p.id, message:'This product has past orders, so it was archived (hidden from store) instead of deleted. Order history stays safe.' });
  }
  db.products.splice(i,1); cleanup(); saveDB(); res.json({ deleted:p.id });
});

/* ---------------- Reviews ---------------- */
app.get('/api/products/:id/reviews', (req,res)=> res.json(db.reviews.filter(r=>r.productId===req.params.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))));
app.post('/api/products/:id/reviews', auth, (req,res)=>{
  const p = db.products.find(x=>x.id===req.params.id);
  if(!p) return res.status(404).json({ error:'Product not found' });
  const { rating, text } = req.body||{};
  if(!rating || !text) return res.status(400).json({ error:'Rating and review text are required' });
  const r = { id:uid('r'), productId:p.id, userName:req.user.name, rating:Math.min(5,Math.max(1,+rating)), text, createdAt:nowISO() };
  db.reviews.push(r);
  const all = db.reviews.filter(x=>x.productId===p.id);
  p.reviewsCount = all.length + 20; // seeded baseline preserved-ish; recompute blend:
  p.rating = Math.round(((all.reduce((s,x)=>s+x.rating,0)/all.length)*0.4 + p.rating*0.6)*10)/10;
  saveDB(); res.status(201).json(r);
});

/* ---------------- Cart (persistent per user; guest handled client-side) ---------------- */
function cartDetailed(userId){
  const items = (db.carts[userId]||[]).map(ci=>{
    const p = db.products.find(x=>x.id===ci.productId);
    return p ? { productId:p.id, name:p.name, image:p.image, metal:p.metal, price:p.price, mrp:p.mrp, stock:p.stock, qty:ci.qty } : null;
  }).filter(Boolean);
  const subtotal = items.reduce((s,i)=>s+i.price*i.qty,0);
  const mrpTotal = items.reduce((s,i)=>s+i.mrp*i.qty,0);
  return { items, subtotal, mrpTotal, savings: mrpTotal-subtotal, count: items.reduce((s,i)=>s+i.qty,0) };
}
app.get('/api/cart', auth, (req,res)=> res.json(cartDetailed(req.user.id)));
app.post('/api/cart', auth, (req,res)=>{
  const { productId, qty=1 } = req.body||{};
  const p = db.products.find(x=>x.id===productId);
  if(!p) return res.status(404).json({ error:'Product not found' });
  if(p.stock<=0) return res.status(400).json({ error:'This item is out of stock' });
  if(!db.carts[req.user.id]) db.carts[req.user.id]=[];
  const ex = db.carts[req.user.id].find(x=>x.productId===productId);
  if(ex) ex.qty = Math.min(p.stock, ex.qty + (+qty||1)); else db.carts[req.user.id].push({ productId, qty: Math.min(p.stock, +qty||1) });
  saveDB(); res.json(cartDetailed(req.user.id));
});
app.put('/api/cart/:productId', auth, (req,res)=>{
  const list = db.carts[req.user.id]||[];
  const it = list.find(x=>x.productId===req.params.productId);
  if(!it) return res.status(404).json({ error:'Item not in cart' });
  const p = db.products.find(x=>x.id===req.params.productId);
  it.qty = Math.max(1, Math.min(p?p.stock:99, +req.body.qty||1));
  saveDB(); res.json(cartDetailed(req.user.id));
});
app.delete('/api/cart/:productId', auth, (req,res)=>{
  db.carts[req.user.id] = (db.carts[req.user.id]||[]).filter(x=>x.productId!==req.params.productId);
  saveDB(); res.json(cartDetailed(req.user.id));
});
app.delete('/api/cart', auth, (req,res)=>{ db.carts[req.user.id]=[]; saveDB(); res.json(cartDetailed(req.user.id)); });

/* ---------------- Wishlist ---------------- */
app.get('/api/wishlist', auth, (req,res)=>{
  const ids = db.wishlists[req.user.id]||[];
  res.json({ ids, products: ids.map(id=>db.products.find(p=>p.id===id)).filter(Boolean) });
});
app.post('/api/wishlist/toggle', auth, (req,res)=>{
  const { productId } = req.body||{};
  if(!db.products.some(p=>p.id===productId)) return res.status(404).json({ error:'Product not found' });
  if(!db.wishlists[req.user.id]) db.wishlists[req.user.id]=[];
  const list = db.wishlists[req.user.id];
  const i = list.indexOf(productId);
  let wished;
  if(i>=0){ list.splice(i,1); wished=false; } else { list.push(productId); wished=true; }
  saveDB(); res.json({ wished, ids:list });
});

/* ---------------- Addresses CRUD ---------------- */
app.get('/api/addresses', auth, (req,res)=> res.json(db.addresses.filter(a=>a.userId===req.user.id)));
app.post('/api/addresses', auth, (req,res)=>{
  const b=req.body||{};
  if(!b.name || !b.phone || !b.line1 || !b.city || !b.state || !b.pincode) return res.status(400).json({ error:'Please fill all address fields' });
  const isFirst = !db.addresses.some(a=>a.userId===req.user.id);
  const a = { id:uid('addr'), userId:req.user.id, label:b.label||'Home', name:b.name, phone:b.phone, line1:b.line1, city:b.city, state:b.state, pincode:b.pincode, isDefault: isFirst || !!b.isDefault };
  if(a.isDefault) db.addresses.forEach(x=>{ if(x.userId===req.user.id) x.isDefault=false; });
  db.addresses.push(a); saveDB(); res.status(201).json(a);
});
app.put('/api/addresses/:id', auth, (req,res)=>{
  const a = db.addresses.find(x=>x.id===req.params.id && x.userId===req.user.id);
  if(!a) return res.status(404).json({ error:'Address not found' });
  Object.assign(a, req.body||{});
  if(a.isDefault) db.addresses.forEach(x=>{ if(x.userId===req.user.id && x.id!==a.id) x.isDefault=false; });
  saveDB(); res.json(a);
});
app.delete('/api/addresses/:id', auth, (req,res)=>{
  const i = db.addresses.findIndex(x=>x.id===req.params.id && x.userId===req.user.id);
  if(i<0) return res.status(404).json({ error:'Address not found' });
  db.addresses.splice(i,1); saveDB(); res.json({ deleted:req.params.id });
});

/* ---------------- Coupons CRUD + validate ---------------- */
app.get('/api/coupons', (req,res)=> res.json(db.coupons.filter(c=>c.active)));
app.get('/api/admin/coupons', auth, adminOnly, (req,res)=> res.json(db.coupons));
app.post('/api/coupons/validate', auth, (req,res)=>{
  const { code, subtotal } = req.body||{};
  const c = db.coupons.find(x=>x.code===String(code||'').toUpperCase() && x.active);
  if(!c) return res.status(400).json({ error:'Invalid or expired coupon code' });
  if(new Date(c.expires) < new Date()) return res.status(400).json({ error:'This coupon has expired' });
  if((+subtotal||0) < c.minOrder) return res.status(400).json({ error:`${c.code} needs a minimum order of ₹${c.minOrder.toLocaleString('en-IN')}` });
  let discount = c.type==='percent' ? Math.floor(subtotal*c.value/100) : c.value;
  discount = Math.min(discount, c.maxDiscount||discount);
  res.json({ code:c.code, discount, message:`${c.code} applied — you save ₹${discount.toLocaleString('en-IN')}!` });
});
app.post('/api/admin/coupons', auth, adminOnly, (req,res)=>{
  const b=req.body||{};
  if(!b.code || b.value==null) return res.status(400).json({ error:'Coupon code and value are required' });
  if(db.coupons.some(c=>c.code===String(b.code).toUpperCase())) return res.status(409).json({ error:'Coupon code already exists' });
  const c = { id:uid('cp'), code:String(b.code).toUpperCase(), type:b.type||'percent', value:+b.value, minOrder:+(b.minOrder||0), maxDiscount:+(b.maxDiscount||999999), expires:b.expires||'2026-12-31', active:b.active!==false, used:0 };
  db.coupons.push(c); saveDB(); res.status(201).json(c);
});
app.put('/api/admin/coupons/:id', auth, adminOnly, (req,res)=>{
  const c = db.coupons.find(x=>x.id===req.params.id);
  if(!c) return res.status(404).json({ error:'Coupon not found' });
  Object.assign(c, req.body||{}); if(c.code) c.code=String(c.code).toUpperCase();
  ['value','minOrder','maxDiscount'].forEach(k=>{ if(c[k]!=null) c[k]=+c[k]; });
  saveDB(); res.json(c);
});
app.delete('/api/admin/coupons/:id', auth, adminOnly, (req,res)=>{
  const i=db.coupons.findIndex(x=>x.id===req.params.id);
  if(i<0) return res.status(404).json({ error:'Coupon not found' });
  db.coupons.splice(i,1); saveDB(); res.json({ deleted:req.params.id });
});

/* ---------------- Orders ---------------- */
app.post('/api/orders', auth, (req,res)=>{
  const { address, payment='UPI', coupon='', items: clientItems } = req.body||{};
  let items;
  if(Array.isArray(clientItems) && clientItems.length){
    items = clientItems.map(ci=>{
      const p = db.products.find(x=>x.id===ci.productId);
      if(!p) return null;
      return { productId:p.id, name:p.name, image:p.image, price:p.price, qty: Math.max(1,+ci.qty||1) };
    }).filter(Boolean);
  } else {
    items = cartDetailed(req.user.id).items.map(i=>({ productId:i.productId, name:i.name, image:i.image, price:i.price, qty:i.qty }));
  }
  if(!items.length) return res.status(400).json({ error:'Your cart is empty' });
  if(!address) return res.status(400).json({ error:'Please select a delivery address' });
  // stock check + decrement
  for(const it of items){
    const p = db.products.find(x=>x.id===it.productId);
    if(!p || p.stock < it.qty) return res.status(400).json({ error:`"${it.name}" has only ${p?p.stock:0} left in stock` });
  }
  items.forEach(it=>{ const p=db.products.find(x=>x.id===it.productId); p.stock-=it.qty; p.sold+=it.qty; });
  const subtotal = items.reduce((s,i)=>s+i.price*i.qty,0);
  let discount = 0;
  if(coupon){
    const c = db.coupons.find(x=>x.code===String(coupon).toUpperCase() && x.active);
    if(c && subtotal>=c.minOrder){ discount = Math.min(c.type==='percent'?Math.floor(subtotal*c.value/100):c.value, c.maxDiscount||999999); c.used++; }
  }
  const shipping = subtotal - discount >= db.settings.freeShipAbove ? 0 : db.settings.shippingFee;
  const order = {
    id:'SON'+(db.orderSeq++), userId:req.user.id, customerName:req.user.name, email:req.user.email, phone:req.user.phone,
    items, subtotal, discount, shipping, total: subtotal - discount + shipping,
    coupon: coupon?String(coupon).toUpperCase():'', payment,
    paymentStatus: payment==='COD' ? 'Pending (COD)' : 'Paid',
    status:'Pending', address, createdAt:nowISO(), timeline:[{s:'Placed', t:nowISO()}]
  };
  db.orders.unshift(order);
  db.carts[req.user.id] = [];
  saveDB(); res.status(201).json(order);
});
app.get('/api/orders', auth, (req,res)=>{
  if(req.user.role==='admin'){
    const { status='', q='' } = req.query;
    let list=[...db.orders];
    if(status) list=list.filter(o=>o.status===status);
    if(q){ const s=q.toLowerCase(); list=list.filter(o=>(o.id+' '+o.customerName+' '+o.email+' '+o.phone).toLowerCase().includes(s)); }
    return res.json(list.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)));
  }
  res.json(db.orders.filter(o=>o.userId===req.user.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)));
});
app.get('/api/orders/:id', auth, (req,res)=>{
  const o = db.orders.find(x=>x.id===req.params.id);
  if(!o) return res.status(404).json({ error:'Order not found' });
  if(req.user.role!=='admin' && o.userId!==req.user.id) return res.status(403).json({ error:'Not your order' });
  res.json(o);
});
app.put('/api/orders/:id/status', auth, adminOnly, (req,res)=>{
  const o = db.orders.find(x=>x.id===req.params.id);
  if(!o) return res.status(404).json({ error:'Order not found' });
  const { status } = req.body||{};
  const allowed=['Pending','Processing','Shipped','Out for Delivery','Delivered','Cancelled'];
  if(!allowed.includes(status)) return res.status(400).json({ error:'Invalid status' });
  if(status==='Cancelled' && o.status!=='Cancelled'){
    o.items.forEach(it=>{ const p=db.products.find(x=>x.id===it.productId); if(p){ p.stock+=it.qty; p.sold=Math.max(0,p.sold-it.qty);} });
    if(o.paymentStatus==='Paid') o.paymentStatus='Refunded';
  }
  if(status==='Delivered' && o.payment==='COD') o.paymentStatus='Paid (COD collected)';
  o.status=status; o.timeline.push({s:status, t:nowISO()});
  saveDB(); res.json(o);
});
app.put('/api/orders/:id/cancel', auth, (req,res)=>{
  const o = db.orders.find(x=>x.id===req.params.id);
  if(!o) return res.status(404).json({ error:'Order not found' });
  if(o.userId!==req.user.id) return res.status(403).json({ error:'Not your order' });
  if(!['Pending','Processing'].includes(o.status)) return res.status(400).json({ error:'This order can no longer be cancelled. Please contact support.' });
  o.items.forEach(it=>{ const p=db.products.find(x=>x.id===it.productId); if(p){ p.stock+=it.qty; p.sold=Math.max(0,p.sold-it.qty);} });
  if(o.paymentStatus==='Paid') o.paymentStatus='Refund initiated';
  o.status='Cancelled'; o.timeline.push({s:'Cancelled', t:nowISO()});
  saveDB(); res.json(o);
});

/* ---------------- Users (admin) ---------------- */
app.get('/api/users', auth, adminOnly, (req,res)=>{
  const list = db.users.map(u=>{
    const os = db.orders.filter(o=>o.userId===u.id);
    return { ...publicUser(u), orderCount: os.length, totalSpent: os.filter(o=>o.status!=='Cancelled').reduce((s,o)=>s+o.total,0), lastOrder: os.length?os.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))[0].createdAt:null };
  });
  res.json(list);
});
app.put('/api/users/:id', auth, adminOnly, (req,res)=>{
  const u = db.users.find(x=>x.id===req.params.id);
  if(!u) return res.status(404).json({ error:'User not found' });
  if(u.id===req.user.id && req.body.active===false) return res.status(400).json({ error:'You cannot block your own admin account' });
  if(req.body.active!=null) u.active=!!req.body.active;
  if(req.body.role && ['admin','customer'].includes(req.body.role)) u.role=req.body.role;
  if(req.body.name) u.name=req.body.name;
  saveDB(); res.json(publicUser(u));
});
app.delete('/api/users/:id', auth, adminOnly, (req,res)=>{
  if(req.params.id===req.user.id) return res.status(400).json({ error:'You cannot delete your own account' });
  const i=db.users.findIndex(x=>x.id===req.params.id);
  if(i<0) return res.status(404).json({ error:'User not found' });
  db.users.splice(i,1); saveDB(); res.json({ deleted:req.params.id });
});

/* ---------------- Stats ---------------- */
app.get('/api/stats/admin', auth, adminOnly, (req,res)=>{
  const live = db.orders.filter(o=>o.status!=='Cancelled');
  const revenue = live.reduce((s,o)=>s+o.total,0);
  const byStatus = {};
  db.orders.forEach(o=> byStatus[o.status]=(byStatus[o.status]||0)+1);
  const last7 = [];
  for(let d=6; d>=0; d--){
    const dt=new Date(); dt.setDate(dt.getDate()-d);
    const key = dt.toISOString().slice(0,10);
    const dayOrders = live.filter(o=>o.createdAt.slice(0,10)===key);
    last7.push({ label: dt.toLocaleDateString('en-IN',{weekday:'short'}), date:key, revenue: dayOrders.reduce((s,o)=>s+o.total,0), orders: dayOrders.length });
  }
  // fill demo history so chart feels alive even with sparse recent orders
  const metalSales = {};
  live.forEach(o=>o.items.forEach(it=>{ const p=db.products.find(x=>x.id===it.productId); const m=p?p.metal:'Imitation'; metalSales[m]=(metalSales[m]||0)+it.price*it.qty; }));
  const topProducts = [...db.products].sort((a,b)=>b.sold-a.sold).slice(0,5).map(p=>({ id:p.id, name:p.name, image:p.image, sold:p.sold, revenue:p.sold*p.price, stock:p.stock }));
  res.json({
    revenue, orderCount: db.orders.length, customerCount: db.users.filter(u=>u.role==='customer').length,
    productCount: db.products.length, avgOrder: live.length?Math.round(revenue/live.length):0,
    pendingOrders: db.orders.filter(o=>o.status==='Pending').length,
    lowStock: db.products.filter(p=>p.stock<=5).map(p=>({id:p.id,name:p.name,stock:p.stock,image:p.image})),
    byStatus, last7, metalSales, topProducts,
    recentOrders: [...db.orders].sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,6)
  });
});
app.get('/api/stats/customer', auth, (req,res)=>{
  const os = db.orders.filter(o=>o.userId===req.user.id);
  res.json({
    orderCount: os.length,
    totalSpent: os.filter(o=>o.status!=='Cancelled').reduce((s,o)=>s+o.total,0),
    wishlistCount: (db.wishlists[req.user.id]||[]).length,
    cartCount: cartDetailed(req.user.id).count,
    recentOrders: os.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,4)
  });
});

/* ---------------- PRO module (v2: OTP/Google, Razorpay, pricing, upload, returns, exports) ---------------- */
require('./pro-routes')({ app, getDB: () => db, saveDB, auth, adminOnly, publicUser, sign, uid, normPhone, cartDetailed });

/* ---------------- SPA fallback ---------------- */
app.get('*', (req,res)=>{
  if(req.path.startsWith('/api/')) return res.status(404).json({ error:'API route not found' });
  res.setHeader('Cache-Control','no-store, must-revalidate'); res.sendFile(path.join(__dirname,'public','index.html'));
});

loadDB(); if (typeof global.__jewelProMigrate==='function') global.__jewelProMigrate();
if(process.argv.includes('--seed')){ db = seed(); saveDB(); console.log('✅ Database reseeded with demo data.'); }
app.listen(PORT, '0.0.0.0', ()=>{
  console.log(`\n💎 Sonara Jewels store running → http://localhost:${PORT}`);
  console.log(`   Admin:    admin@sonara.in / admin123  (phone 9876543210)`);
  console.log(`   Staff:    staff@sonara.in / staff123`); console.log(`   Customer: priya@example.com / customer123  (phone 9825012345)\n`);
});
