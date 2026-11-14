# 💎 Jewellery Store PRO v2 — Sellable Software for Jewellers

White-label e-commerce for **one jewellery shop per installation** (Gold • Silver • Imitation): Website (PC+Mobile) + Android-ready, one backend.

**New in v2:** Mobile OTP + Google Login • Razorpay (UPI/Cards/EMI) + COD with TEST mode • Live metal-rate weight pricing • Image upload • Staff roles • Courier AWB + Returns/Refunds • GST invoice fields • CSV exports • 🚀 Setup Wizard for buyers

## Quick start
```bash
npm install
cp .env.example .env   # fill keys, or keep TEST MODE for demos
npm start              # http://localhost:3000
```
Logins: Admin `admin@sonara.in/admin123` • Staff `staff@sonara.in/staff123` • Customer `priya@example.com/customer123` (login by email OR mobile; OTP test number: any 10-digit in dev mode)

## Docs (read in this order)
1. `docs/WHAT-I-NEED-FROM-YOU.md` — seller + buyer checklist
2. `docs/HOW-TO-USE-AND-SELL.md` — daily use, pricing packs, handover & update process
3. `docs/NEXT-UPDATE-IDEAS.md` — P0/P1/P2 roadmap

Data lives in `data/db.json` (+ auto `.backup`); uploaded photos in `public/uploads/`; secrets ONLY in `.env`. Reset demo: stop server → delete `data/db.json` → restart.
