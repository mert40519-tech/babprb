#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Escrow Bot v2.0 - Single file Telegram escrow bot
Features: IBAN manual payment, Crypto auto-check, Admin panel
Setup: pip install aiogram==3.7.0 aiosqlite aiohttp tronpy eth-account
"""

import asyncio, logging, secrets, hashlib, json, os
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple

import aiosqlite, aiohttp
from aiogram import Bot, Dispatcher, Router, F
from aiogram.client.default import DefaultBotProperties
from aiogram.types import (
    Message, CallbackQuery,
    InlineKeyboardMarkup, InlineKeyboardButton,
    ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
)
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

# ════════════════════════════════════════════════════════
#  YAPILANDIRMA  ← BURADAN DEĞİŞTİR
# ════════════════════════════════════════════════════════
BOT_TOKEN     = os.getenv("BOT_TOKEN",    "8698709943:AAE3ZVzjyMSE9elndQCJo-9dVTWsgG41ABY")
ADMIN_IDS     = [int(x) for x in os.getenv("ADMIN_IDS", "7672180974").split(",") if x.strip()]
DB_PATH       = os.getenv("DB_PATH",      "escrow.db")
FEE_PERCENT   = float(os.getenv("FEE_PERCENT",   "2.0"))
PAYMENT_HOURS = int(os.getenv("PAYMENT_HOURS",   "24"))
MONITOR_SEC   = int(os.getenv("MONITOR_SEC",     "30"))
TRON_API_KEY  = os.getenv("TRON_API_KEY", "")
# ════════════════════════════════════════════════════════

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

COINS = {
    "USDT_TRC20": "💎 USDT (TRC20)",
    "TRX":        "⚡ TRX",
    "ETH":        "🔷 ETH",
    "BTC":        "₿ BTC",
}

# ════════════════════════════════════════════════════════
#  VERİTABANI
# ════════════════════════════════════════════════════════

async def db_init():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);

        CREATE TABLE IF NOT EXISTS users(
            user_id   INTEGER PRIMARY KEY,
            username  TEXT, full_name TEXT,
            is_banned INTEGER DEFAULT 0,
            created_at TEXT DEFAULT(datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS deals(
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            code       TEXT UNIQUE,
            buyer_id   INTEGER, seller_id INTEGER, creator_id INTEGER,
            amount     REAL, currency TEXT DEFAULT 'TRY',
            description TEXT, method TEXT,
            status     TEXT DEFAULT 'pending',
            deadline   TEXT,
            created_at TEXT DEFAULT(datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS crypto_addr(
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_id  INTEGER, coin TEXT,
            address  TEXT UNIQUE, privkey TEXT,
            expected REAL, received REAL DEFAULT 0,
            status   TEXT DEFAULT 'waiting',
            tx_hash  TEXT,
            created_at TEXT DEFAULT(datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS iban_pay(
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_id  INTEGER, iban TEXT, bank TEXT, holder TEXT,
            amount   REAL, currency TEXT,
            status   TEXT DEFAULT 'waiting',
            admin_id INTEGER, confirmed_at TEXT,
            created_at TEXT DEFAULT(datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS txlog(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_id INTEGER, type TEXT,
            amount REAL, currency TEXT,
            from_address TEXT, to_address TEXT,
            tx_hash TEXT, note TEXT,
            created_at TEXT DEFAULT(datetime('now'))
        );
        """)
        await db.commit()

async def cfg_get(key: str, default=None):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT value FROM settings WHERE key=?", (key,)) as c:
            r = await c.fetchone()
            if r:
                try: return json.loads(r[0])
                except: return r[0]
            return default

async def cfg_set(key: str, value):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
                         (key, json.dumps(value)))
        await db.commit()

async def one(q: str, p: tuple = ()) -> Optional[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(q, p) as c:
            r = await c.fetchone()
            return dict(r) if r else None

async def many(q: str, p: tuple = ()) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(q, p) as c:
            return [dict(r) for r in await c.fetchall()]

async def exe(q: str, p: tuple = ()) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        c = await db.execute(q, p)
        await db.commit()
        return c.lastrowid

# ════════════════════════════════════════════════════════
#  KRİPTO CÜZDAN ÜRETİCİ
# ════════════════════════════════════════════════════════

def gen_tron() -> Tuple[str, str]:
    try:
        from tronpy.keys import PrivateKey
        pk = PrivateKey(secrets.token_bytes(32))
        return pk.public_key.to_base58check_address(), pk.hex()
    except Exception:
        priv = secrets.token_hex(32)
        raw = hashlib.sha256(bytes.fromhex(priv)).digest()
        chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        addr = "T" + "".join(chars[b % 58] for b in raw[:33])
        return addr, priv

def gen_eth() -> Tuple[str, str]:
    try:
        from eth_account import Account
        a = Account.create(extra_entropy=secrets.token_hex(32))
        return a.address, a.key.hex()
    except Exception:
        priv = "0x" + secrets.token_hex(32)
        h = hashlib.sha256(priv.encode()).hexdigest()
        return "0x" + h[:40], priv

def gen_btc() -> Tuple[str, str]:
    priv = secrets.token_hex(32)
    raw = hashlib.sha256(bytes.fromhex(priv)).digest()
    chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    addr = "1" + "".join(chars[b % 58] for b in raw[:33])
    return addr, priv

def generate_address(coin: str) -> Tuple[str, str]:
    c = coin.upper()
    if c in ("TRX", "USDT_TRC20"): return gen_tron()
    if c in ("ETH", "USDT_ERC20"): return gen_eth()
    if c == "BTC": return gen_btc()
    raise ValueError(f"Bilinmeyen coin: {coin}")

# ════════════════════════════════════════════════════════
#  BLOCKCHAIN BAKIYE SORGULAMA
# ════════════════════════════════════════════════════════

async def _get(url: str, headers: dict = None) -> dict:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, headers=headers or {},
                             timeout=aiohttp.ClientTimeout(total=12)) as r:
                return await r.json(content_type=None)
    except Exception as e:
        log.warning(f"HTTP GET hatası {url}: {e}")
        return {}

async def bal_trx(address: str) -> float:
    h = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}
    d = await _get(f"https://api.trongrid.io/v1/accounts/{address}", h)
    return d.get("data", [{}])[0].get("balance", 0) / 1_000_000

async def bal_usdt_trc20(address: str) -> float:
    h = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}
    d = await _get(f"https://api.trongrid.io/v1/accounts/{address}/tokens", h)
    for t in d.get("data", []):
        if t.get("tokenId") == USDT_TRC20_CONTRACT or t.get("tokenAbbr") == "USDT":
            return float(t.get("balance", 0)) / 1_000_000
    return 0.0

async def bal_eth(address: str) -> float:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post("https://cloudflare-eth.com",
                              json={"jsonrpc":"2.0","method":"eth_getBalance",
                                    "params":[address,"latest"],"id":1},
                              timeout=aiohttp.ClientTimeout(total=12)) as r:
                d = await r.json()
                return int(d.get("result","0x0"), 16) / 1e18
    except Exception:
        return 0.0

async def bal_btc(address: str) -> float:
    d = await _get(f"https://blockstream.info/api/address/{address}")
    cs = d.get("chain_stats", {})
    return (cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)) / 1e8

async def get_balance(coin: str, address: str) -> float:
    c = coin.upper()
    if c == "TRX":         return await bal_trx(address)
    if c == "USDT_TRC20":  return await bal_usdt_trc20(address)
    if c == "ETH":         return await bal_eth(address)
    if c == "BTC":         return await bal_btc(address)
    return 0.0

# ════════════════════════════════════════════════════════
#  KRİPTO GÖNDERME
# ════════════════════════════════════════════════════════

async def send_tron(from_addr: str, privkey: str, to_addr: str,
                    amount: float, coin: str) -> Optional[str]:
    try:
        from tronpy import Tron
        from tronpy.keys import PrivateKey
        from tronpy.providers import HTTPProvider
        provider = HTTPProvider(api_key=TRON_API_KEY) if TRON_API_KEY else None
        client = Tron(provider=provider)
        pk = PrivateKey(bytes.fromhex(privkey))
        if coin == "TRX":
            txn = (client.trx.transfer(from_addr, to_addr, int(amount * 1_000_000))
                   .memo("Escrow").build().sign(pk))
        else:
            contract = client.get_contract(USDT_TRC20_CONTRACT)
            txn = (contract.functions.transfer(to_addr, int(amount * 1_000_000))
                   .with_owner(from_addr).fee_limit(20_000_000).build().sign(pk))
        res = txn.broadcast().wait()
        return res.get("id") or res.get("txid")
    except Exception as e:
        log.error(f"Tron gönderim hatası: {e}")
        return None

async def send_eth(privkey: str, to_addr: str, amount: float) -> Optional[str]:
    try:
        from eth_account import Account
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider("https://cloudflare-eth.com"))
        acct = Account.from_key(privkey)
        tx = {"to": to_addr, "value": w3.to_wei(amount, "ether"),
              "gas": 21000, "gasPrice": w3.eth.gas_price,
              "nonce": w3.eth.get_transaction_count(acct.address), "chainId": 1}
        signed = acct.sign_transaction(tx)
        return w3.eth.send_raw_transaction(signed.rawTransaction).hex()
    except Exception as e:
        log.error(f"ETH gönderim hatası: {e}")
        return None

# ════════════════════════════════════════════════════════
#  YARDIMCI
# ════════════════════════════════════════════════════════

def gen_code() -> str:
    return secrets.token_hex(4).upper()

def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS

def st_emoji(s: str) -> str:
    return {"pending":"⏳","payment_pending":"💳","paid":"✅","confirmed":"🔐",
            "released":"💸","cancelled":"❌","disputed":"⚠️"}.get(s, "❓")

def deal_text(d: Dict) -> str:
    return (f"{st_emoji(d['status'])} <b>Anlaşma #{d['code']}</b>\n"
            f"💰 {d['amount']} {d['currency']}\n"
            f"📦 {d['description']}\n"
            f"💳 {d.get('method','—')}\n"
            f"📊 Durum: <b>{d['status']}</b>\n"
            f"📅 {d['created_at'][:16]}")

def ikb(*rows) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t, callback_data=d) for t, d in row]
        for row in rows
    ])

def main_kb(uid: int) -> ReplyKeyboardMarkup:
    rows = [
        [KeyboardButton(text="📋 Anlaşma Oluştur"), KeyboardButton(text="📂 Anlaşmalarım")],
        [KeyboardButton(text="ℹ️ Nasıl Çalışır"),   KeyboardButton(text="💬 Destek")],
    ]
    if is_admin(uid):
        rows.append([KeyboardButton(text="👑 Admin Panel")])
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True)

# ════════════════════════════════════════════════════════
#  FSM STATES
# ════════════════════════════════════════════════════════

class Deal(StatesGroup):
    partner  = State()
    role     = State()
    amount   = State()
    currency = State()
    desc     = State()
    method   = State()
    confirm  = State()

class Adm(StatesGroup):
    iban_val    = State()
    iban_bank   = State()
    iban_holder = State()
    send_to     = State()
    send_amt    = State()
    broadcast   = State()
    ban_uid     = State()

# ════════════════════════════════════════════════════════
#  ROUTERLAR
# ════════════════════════════════════════════════════════

user_r  = Router()
admin_r = Router()

# ════════════════════════════════════════════════════════
#  KULLANICI — GENEL
# ════════════════════════════════════════════════════════

@user_r.message(CommandStart())
async def cmd_start(msg: Message, state: FSMContext):
    await state.clear()
    await exe(
        "INSERT OR REPLACE INTO users(user_id,username,full_name) VALUES(?,?,?)",
        (msg.from_user.id, msg.from_user.username or "", msg.from_user.full_name or "")
    )
    u = await one("SELECT is_banned FROM users WHERE user_id=?", (msg.from_user.id,))
    if u and u["is_banned"]:
        await msg.answer("🚫 Hesabınız yasaklandı.")
        return
    await msg.answer(
        "🔐 <b>Escrow Bot'a Hoş Geldiniz!</b>\n\n"
        "Alıcı ve satıcı arasında güvenli ödeme aracılığı yapıyoruz.\n"
        "Para önce botta tutulur, teslim sonrası satıcıya aktarılır.\n\n"
        f"💸 Komisyon: <b>%{FEE_PERCENT}</b> | ⏰ Ödeme süresi: <b>{PAYMENT_HOURS} saat</b>",
        reply_markup=main_kb(msg.from_user.id)
    )

@user_r.message(F.text == "ℹ️ Nasıl Çalışır")
async def how_works(msg: Message):
    await msg.answer(
        "📖 <b>Nasıl Çalışır?</b>\n\n"
        "1️⃣ <b>Anlaşma Oluştur</b> — Karşı tarafın ID'sini gir, rolünü seç\n"
        "2️⃣ <b>Ödeme Yap</b>\n"
        "   • IBAN: Admin hesabına havale → Admin onaylar\n"
        "   • Kripto: Özel adrese gönder → Otomatik kontrol edilir\n"
        "3️⃣ <b>Teslim Al</b> — Onay ver → Para satıcıya gönderilir\n\n"
        "⚠️ Sorun olursa Dispute açabilirsin, admin çözer."
    )

@user_r.message(F.text == "💬 Destek")
async def support(msg: Message):
    await msg.answer("💬 Destek için adminle iletişime geç.")

# ════════════════════════════════════════════════════════
#  ANLAŞMALARıM
# ════════════════════════════════════════════════════════

@user_r.message(F.text == "📂 Anlaşmalarım")
async def my_deals(msg: Message):
    uid = msg.from_user.id
    deals = await many(
        "SELECT * FROM deals WHERE buyer_id=? OR seller_id=? ORDER BY created_at DESC LIMIT 10",
        (uid, uid)
    )
    if not deals:
        await msg.answer("📭 Henüz anlaşmanız yok.", reply_markup=main_kb(uid))
        return

    await msg.answer(f"📂 <b>Son {len(deals)} Anlaşmanız:</b>")
    for d in deals:
        role = "🛒 Alıcı" if d["buyer_id"] == uid else "🏪 Satıcı"
        btns = []
        if d["status"] in ("payment_pending", "pending"):
            btns.append([("💳 Ödeme Bilgisi", f"pay_info:{d['id']}")])
        if d["status"] == "confirmed" and d["buyer_id"] == uid:
            btns.append([("✅ Teslim Onayı", f"release:{d['id']}"),
                         ("⚠️ Dispute Aç", f"dispute:{d['id']}")])
        btns.append([("🔍 Detay", f"detail:{d['id']}")])
        await msg.answer(f"👤 {role}\n\n{deal_text(d)}", reply_markup=ikb(*btns))

@user_r.callback_query(F.data.startswith("detail:"))
async def deal_detail(call: CallbackQuery):
    did = int(call.data.split(":")[1])
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d:
        await call.answer("Bulunamadı", show_alert=True); return
    if call.from_user.id not in (d["buyer_id"], d["seller_id"]) and not is_admin(call.from_user.id):
        await call.answer("❌ Yetkisiz", show_alert=True); return

    extra = ""
    if d["method"] == "IBAN":
        ip = await one("SELECT * FROM iban_pay WHERE deal_id=? ORDER BY id DESC LIMIT 1", (did,))
        if ip:
            extra = (f"\n\n🏦 IBAN: <code>{ip['iban']}</code>\n"
                     f"Banka: {ip['bank']} | Sahip: {ip['holder']}\n"
                     f"Durum: {ip['status']}")
    else:
        ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (did,))
        if ca:
            extra = (f"\n\n🔗 Adres: <code>{ca['address']}</code>\n"
                     f"Beklenen: {ca['expected']} | Alınan: {ca['received']}\n"
                     f"Durum: {ca['status']}")

    await call.message.edit_text(deal_text(d) + extra)
    await call.answer()

@user_r.callback_query(F.data.startswith("pay_info:"))
async def pay_info(call: CallbackQuery):
    did = int(call.data.split(":")[1])
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d:
        await call.answer("Bulunamadı", show_alert=True); return

    if d["method"] == "IBAN":
        ip = await one("SELECT * FROM iban_pay WHERE deal_id=? ORDER BY id DESC LIMIT 1", (did,))
        iban_info = await cfg_get("iban_info", {})
        iban = iban_info.get("iban", "Henüz ayarlanmadı")
        bank = iban_info.get("bank", "—")
        holder = iban_info.get("holder", "—")
        await call.message.answer(
            f"🏦 <b>IBAN Ödeme Bilgileri</b>\n\n"
            f"Banka: <b>{bank}</b>\n"
            f"Hesap Sahibi: <b>{holder}</b>\n"
            f"IBAN: <code>{iban}</code>\n\n"
            f"💰 Gönderilecek: <b>{d['amount']} {d['currency']}</b>\n"
            f"📝 Açıklama: <b>ESCROW-{d['code']}</b>\n\n"
            f"⚠️ Ödeme sonrası admin onaylayacak, bekleyin."
        )
    else:
        ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (did,))
        if ca:
            await call.message.answer(
                f"🔗 <b>{COINS.get(d['method'], d['method'])} Ödeme Adresi</b>\n\n"
                f"<code>{ca['address']}</code>\n\n"
                f"💰 Gönderilecek: <b>{ca['expected']} {d['method']}</b>\n"
                f"⏰ Süre: {PAYMENT_HOURS} saat\n\n"
                f"✅ Ödeme otomatik kontrol edilir."
            )
    await call.answer()

# ════════════════════════════════════════════════════════
#  TESLİM ONAYI
# ════════════════════════════════════════════════════════

@user_r.callback_query(F.data.startswith("release:"))
async def release_ask(call: CallbackQuery):
    did = int(call.data.split(":")[1])
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d or d["buyer_id"] != call.from_user.id:
        await call.answer("❌ Yetkisiz", show_alert=True); return
    if d["status"] != "confirmed":
        await call.answer("⚠️ Bu anlaşma onay beklemede değil", show_alert=True); return
    await call.message.answer(
        f"⚠️ <b>Emin misiniz?</b>\n\n"
        f"<b>{d['amount']} {d['currency']}</b> satıcıya gönderilecek.\nBu geri alınamaz!",
        reply_markup=ikb(
            [("✅ Evet, Serbest Bırak", f"release_ok:{did}")],
            [("❌ İptal", "close")]
        )
    )
    await call.answer()

@user_r.callback_query(F.data.startswith("release_ok:"))
async def release_ok(call: CallbackQuery, bot: Bot):
    did = int(call.data.split(":")[1])
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d or d["buyer_id"] != call.from_user.id:
        await call.answer("❌ Yetkisiz", show_alert=True); return

    await exe("UPDATE deals SET status='released' WHERE id=?", (did,))
    fee = d["amount"] * FEE_PERCENT / 100
    net = round(d["amount"] - fee, 6)

    # Satıcıya bildir
    try:
        await bot.send_message(
            d["seller_id"],
            f"🎉 <b>Ödeme Serbest Bırakıldı!</b>\n\n"
            f"Anlaşma #{d['code']} onaylandı.\n"
            f"💰 Net: <b>{net} {d['currency']}</b> (komisyon: {fee:.2f})"
        )
    except Exception: pass

    # Admine bildir
    for aid in ADMIN_IDS:
        try:
            await bot.send_message(aid,
                f"💸 <b>#{d['code']} Serbest Bırakıldı</b>\n"
                f"Satıcı: {d['seller_id']} | Net: {net} {d['currency']}",
                reply_markup=ikb(
                    [("💸 Kripto Gönder", f"adm_payout:{did}")],
                    [("✅ IBAN Gönderildi", f"adm_iban_done:{did}")]
                )
            )
        except Exception: pass

    # Kripto ise otomatik payout başlat
    if d["method"] in COINS:
        asyncio.create_task(start_payout(bot, d, net))

    try:
        await call.message.edit_text("✅ Para serbest bırakıldı! Satıcıya bildirim gönderildi.")
    except Exception:
        await call.message.answer("✅ Para serbest bırakıldı!")
    await call.answer()

async def start_payout(bot: Bot, deal: Dict, net: float):
    """Satıcıdan kripto adres iste"""
    await bot.send_message(
        deal["seller_id"],
        f"💸 <b>Kripto Ödemeniz Hazır!</b>\n\n"
        f"Tutar: <b>{net} {deal['method']}</b>\n\n"
        f"📬 {deal['method']} adresinizi gönderin:"
    )
    await cfg_set(f"payout_{deal['id']}", {
        "seller_id": deal["seller_id"],
        "deal_id":   deal["id"],
        "coin":      deal["method"],
        "amount":    net
    })

# Satıcı adres mesajını yakala
@user_r.message(F.text)
async def catch_payout_address(msg: Message, bot: Bot):
    uid = msg.from_user.id
    keys = await many("SELECT key, value FROM settings WHERE key LIKE 'payout_%'")
    for row in keys:
        try: data = json.loads(row["value"])
        except: continue
        if data.get("seller_id") != uid: continue

        addr = msg.text.strip()
        coin = data["coin"]
        valid = (
            (coin in ("TRX","USDT_TRC20") and addr.startswith("T") and len(addr) == 34) or
            (coin == "ETH" and addr.startswith("0x") and len(addr) == 42) or
            (coin == "BTC" and (addr.startswith("1") or addr.startswith("3") or addr.startswith("bc1")))
        )
        if not valid:
            await msg.answer(f"❌ Geçersiz {coin} adresi. Tekrar deneyin:"); return

        ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (data["deal_id"],))
        if not ca:
            await msg.answer("❌ Kripto adres kaydı bulunamadı."); return

        await msg.answer(f"⏳ <b>{data['amount']} {coin}</b> gönderiliyor...")
        tx = None
        if coin in ("TRX","USDT_TRC20"):
            tx = await send_tron(ca["address"], ca["privkey"], addr, data["amount"], coin)
        elif coin == "ETH":
            tx = await send_eth(ca["privkey"], addr, data["amount"])

        if tx:
            await msg.answer(f"✅ <b>Gönderildi!</b>\n\nTX: <code>{tx}</code>")
            await exe(
                "INSERT INTO txlog(deal_id,type,amount,currency,to_address,tx_hash) VALUES(?,?,?,?,?,?)",
                (data["deal_id"], "payout", data["amount"], coin, addr, tx)
            )
        else:
            await msg.answer("⚠️ Otomatik gönderim başarısız. Admin manuel yapacak.")
            for aid in ADMIN_IDS:
                try:
                    await bot.send_message(aid,
                        f"🚨 Kripto gönderim BAŞARISIZ!\n"
                        f"Deal #{data['deal_id']} | {data['amount']} {coin}\n"
                        f"Hedef: {addr}"
                    )
                except: pass

        await exe("DELETE FROM settings WHERE key=?", (row["key"],))
        return

# ════════════════════════════════════════════════════════
#  DİSPUTE
# ════════════════════════════════════════════════════════

@user_r.callback_query(F.data.startswith("dispute:"))
async def dispute(call: CallbackQuery, bot: Bot):
    did = int(call.data.split(":")[1])
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d: return
    await exe("UPDATE deals SET status='disputed' WHERE id=?", (did,))
    for aid in ADMIN_IDS:
        try:
            await bot.send_message(aid,
                f"⚠️ <b>Dispute!</b>\n#{d['code']} | {d['amount']} {d['currency']}\n"
                f"Alıcı: {d['buyer_id']} | Satıcı: {d['seller_id']}",
                reply_markup=ikb(
                    [("✅ Alıcı Haklı", f"adm_dis_buyer:{did}"),
                     ("✅ Satıcı Haklı", f"adm_dis_seller:{did}")]
                )
            )
        except: pass
    await call.message.answer("⚠️ Dispute açıldı. Admin müdahale edecek.")
    await call.answer()

@user_r.callback_query(F.data == "close")
async def close_cb(call: CallbackQuery):
    try: await call.message.delete()
    except: pass
    await call.answer()

# ════════════════════════════════════════════════════════
#  ANLAŞMALARıM OLUŞTURMA FSM
# ════════════════════════════════════════════════════════

CANCEL_KB = ReplyKeyboardMarkup(
    keyboard=[[KeyboardButton(text="❌ İptal")]],
    resize_keyboard=True
)

@user_r.message(F.text == "📋 Anlaşma Oluştur")
async def deal_start(msg: Message, state: FSMContext):
    u = await one("SELECT is_banned FROM users WHERE user_id=?", (msg.from_user.id,))
    if u and u["is_banned"]:
        await msg.answer("🚫 Hesabınız yasaklandı."); return
    await state.clear()
    await state.set_state(Deal.partner)
    await msg.answer(
        "👥 <b>Yeni Anlaşma - Adım 1/6</b>\n\n"
        "Karşı tarafın <b>Telegram ID</b> veya <b>@kullanıcıadı</b>:\n"
        "<i>ID öğrenmek için: @userinfobot</i>",
        reply_markup=CANCEL_KB
    )

@user_r.message(StateFilter(Deal.partner))
async def deal_partner(msg: Message, state: FSMContext):
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal edildi.", reply_markup=main_kb(msg.from_user.id)); return

    text = msg.text.strip()
    partner_id = None
    if text.startswith("@"):
        u = await one("SELECT user_id FROM users WHERE username=?", (text[1:],))
        if u: partner_id = u["user_id"]
        else:
            await msg.answer("❌ Kullanıcı bulunamadı. Bot ile konuşmaları gerek."); return
    else:
        try: partner_id = int(text)
        except:
            await msg.answer("❌ Geçersiz. Sayı veya @kullanıcıadı girin."); return

    if partner_id == msg.from_user.id:
        await msg.answer("❌ Kendinizle anlaşma olamaz!"); return

    await state.update_data(partner_id=partner_id)
    await state.set_state(Deal.role)
    await msg.answer(
        f"✅ Karşı taraf: <code>{partner_id}</code>\n\n"
        "👤 <b>Adım 2/6 — Rolünüz nedir?</b>",
        reply_markup=ikb(
            [("🛒 Ben Alıcıyım (ödeyeceğim)", "role:buyer")],
            [("🏪 Ben Satıcıyım (alacağım)", "role:seller")]
        )
    )

@user_r.callback_query(F.data.startswith("role:"), StateFilter(Deal.role))
async def deal_role(call: CallbackQuery, state: FSMContext):
    await state.update_data(role=call.data.split(":")[1])
    await state.set_state(Deal.amount)
    await call.message.answer(
        "💰 <b>Adım 3/6 — Tutar girin:</b>\n"
        "Örnek: <code>500</code> veya <code>1250.50</code>",
        reply_markup=CANCEL_KB
    )
    await call.answer()

@user_r.message(StateFilter(Deal.amount))
async def deal_amount(msg: Message, state: FSMContext):
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id)); return
    try:
        amount = float(msg.text.replace(",", ".").strip())
        if amount <= 0: raise ValueError
    except:
        await msg.answer("❌ Geçersiz tutar."); return

    await state.update_data(amount=amount)
    await state.set_state(Deal.currency)
    await msg.answer(
        "💱 <b>Adım 4/6 — Para birimi:</b>",
        reply_markup=ikb(
            [("🇹🇷 TRY", "cur:TRY"), ("💵 USD", "cur:USD")],
            [("💶 EUR", "cur:EUR"), ("💲 USDT", "cur:USDT")]
        )
    )

@user_r.callback_query(F.data.startswith("cur:"), StateFilter(Deal.currency))
async def deal_currency(call: CallbackQuery, state: FSMContext):
    await state.update_data(currency=call.data.split(":")[1])
    await state.set_state(Deal.desc)
    await call.message.answer(
        "📝 <b>Adım 5/6 — Konu/Açıklama:</b>\n"
        "<i>Örnek: Web sitesi tasarımı - 3 sayfa</i>",
        reply_markup=CANCEL_KB
    )
    await call.answer()

@user_r.message(StateFilter(Deal.desc))
async def deal_desc(msg: Message, state: FSMContext):
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id)); return
    if len(msg.text.strip()) < 5:
        await msg.answer("❌ Çok kısa açıklama."); return

    await state.update_data(description=msg.text.strip())
    await state.set_state(Deal.method)
    await msg.answer(
        "💳 <b>Adım 6/6 — Ödeme Yöntemi:</b>",
        reply_markup=ikb(
            [("🏦 IBAN (Havale/EFT)", "mth:IBAN")],
            [("💎 USDT TRC20", "mth:USDT_TRC20"), ("⚡ TRX", "mth:TRX")],
            [("🔷 ETH", "mth:ETH"), ("₿ BTC", "mth:BTC")]
        )
    )

@user_r.callback_query(F.data.startswith("mth:"), StateFilter(Deal.method))
async def deal_method(call: CallbackQuery, state: FSMContext):
    method = call.data.split(":")[1]
    await state.update_data(method=method)
    await state.set_state(Deal.confirm)

    data = await state.get_data()
    fee = data["amount"] * FEE_PERCENT / 100
    mlabel = "IBAN Havale" if method == "IBAN" else COINS.get(method, method)
    await call.message.answer(
        f"📋 <b>Onay — Anlaşma Özeti</b>\n\n"
        f"👤 Karşı taraf: <code>{data['partner_id']}</code>\n"
        f"👔 Rolünüz: {'Alıcı' if data['role']=='buyer' else 'Satıcı'}\n"
        f"💰 Tutar: <b>{data['amount']} {data['currency']}</b>\n"
        f"💸 Komisyon: {fee:.2f} {data['currency']} (%{FEE_PERCENT})\n"
        f"📦 Konu: {data['description']}\n"
        f"💳 Ödeme: {mlabel}\n\n"
        f"Onaylıyor musunuz?",
        reply_markup=ikb(
            [("✅ Onayla", "dcreate:yes")],
            [("❌ İptal", "dcreate:no")]
        )
    )
    await call.answer()

@user_r.callback_query(F.data.startswith("dcreate:"), StateFilter(Deal.confirm))
async def deal_confirm(call: CallbackQuery, state: FSMContext, bot: Bot):
    if call.data == "dcreate:no":
        await state.clear()
        await call.message.answer("❌ İptal.", reply_markup=main_kb(call.from_user.id))
        await call.answer(); return

    data = await state.get_data()
    await state.clear()

    code = gen_code()
    deadline = (datetime.now() + timedelta(hours=PAYMENT_HOURS)).isoformat()
    uid = call.from_user.id
    buyer_id  = uid if data["role"] == "buyer"  else data["partner_id"]
    seller_id = uid if data["role"] == "seller" else data["partner_id"]
    method    = data["method"]

    deal_id = await exe(
        """INSERT INTO deals(code,buyer_id,seller_id,creator_id,amount,currency,
           description,method,status,deadline) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (code, buyer_id, seller_id, uid,
         data["amount"], data["currency"],
         data["description"], method, "payment_pending", deadline)
    )

    # Ödeme kaydı
    if method == "IBAN":
        ii = await cfg_get("iban_info", {})
        await exe(
            "INSERT INTO iban_pay(deal_id,iban,bank,holder,amount,currency) VALUES(?,?,?,?,?,?)",
            (deal_id, ii.get("iban","—"), ii.get("bank","—"), ii.get("holder","—"),
             data["amount"], data["currency"])
        )
    else:
        addr, privkey = generate_address(method)
        await exe(
            "INSERT INTO crypto_addr(deal_id,coin,address,privkey,expected) VALUES(?,?,?,?,?)",
            (deal_id, method, addr, privkey, data["amount"])
        )

    # Karşı tarafı bilgilendir
    partner_role = "Satıcı" if data["role"] == "buyer" else "Alıcı"
    try:
        await bot.send_message(
            data["partner_id"],
            f"📋 <b>Yeni Escrow Anlaşması!</b>\n\n"
            f"Kod: <b>#{code}</b> | Rolünüz: <b>{partner_role}</b>\n"
            f"Tutar: <b>{data['amount']} {data['currency']}</b>\n"
            f"Konu: {data['description']}",
            reply_markup=ikb([("📋 Anlaşmayı Gör", f"detail:{deal_id}")])
        )
    except Exception: pass

    # Ödeme bilgisi göster
    if method == "IBAN":
        ii = await cfg_get("iban_info", {})
        txt = (f"✅ <b>Anlaşma #{code} Oluşturuldu!</b>\n\n"
               f"🏦 Banka: {ii.get('bank','—')}\n"
               f"👤 Sahip: {ii.get('holder','—')}\n"
               f"💳 IBAN: <code>{ii.get('iban','Henüz ayarlanmadı')}</code>\n\n"
               f"💰 Gönder: <b>{data['amount']} {data['currency']}</b>\n"
               f"📝 Açıklama: <b>ESCROW-{code}</b>")
    else:
        ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (deal_id,))
        txt = (f"✅ <b>Anlaşma #{code} Oluşturuldu!</b>\n\n"
               f"🔗 {COINS.get(method, method)} Adresi:\n"
               f"<code>{ca['address']}</code>\n\n"
               f"💰 Gönder: <b>{data['amount']} {method}</b>\n"
               f"⏰ Süre: {PAYMENT_HOURS} saat\n✅ Otomatik kontrol edilir.")

    await call.message.answer(txt, reply_markup=main_kb(uid))
    await call.answer()

# ════════════════════════════════════════════════════════
#  ADMİN PANEL
# ════════════════════════════════════════════════════════

def admin_kb() -> InlineKeyboardMarkup:
    return ikb(
        [("🏦 IBAN Ayarla",       "adm:iban"),
         ("📋 Bekleyen IBAN",     "adm:pending_iban")],
        [("💎 Kripto Bakiyeler",  "adm:balances"),
         ("💸 Fon Gönder",       "adm:send")],
        [("📊 Tüm Anlaşmalar",   "adm:deals"),
         ("⚠️ Disputelar",       "adm:disputes")],
        [("👥 Kullanıcılar",     "adm:users"),
         ("📢 Duyuru",           "adm:broadcast")],
        [("📈 İstatistikler",    "adm:stats")]
    )

@admin_r.message(Command("admin"))
async def admin_panel_cmd(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id):
        await msg.answer("🚫 Yetkisiz erişim!"); return
    await state.clear()
    await msg.answer("👑 <b>Admin Paneli</b>", reply_markup=admin_kb())

@admin_r.message(F.text == "👑 Admin Panel")
async def admin_panel_btn(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id):
        await msg.answer("🚫 Yetkisiz erişim!"); return
    await state.clear()
    await msg.answer("👑 <b>Admin Paneli</b>", reply_markup=admin_kb())

@admin_r.callback_query(F.data.startswith("adm:"))
async def admin_cb(call: CallbackQuery, state: FSMContext, bot: Bot):
    if not is_admin(call.from_user.id):
        await call.answer("🚫 Yetkisiz!", show_alert=True); return

    action = call.data.split(":")[1]

    # ── IBAN AYARLA ──────────────────────────────────────────────
    if action == "iban":
        ii = await cfg_get("iban_info", {})
        cur = (f"\n\nMevcut:\n<code>{ii.get('iban','Yok')}</code>\n"
               f"{ii.get('bank','—')} | {ii.get('holder','—')}") if ii else ""
        await state.set_state(Adm.iban_val)
        await call.message.answer(
            f"🏦 <b>IBAN Ayarla</b>{cur}\n\nYeni IBAN girin (TR... 26 karakter):",
            reply_markup=CANCEL_KB
        )

    # ── BEKLEYENLERİ GÖR ────────────────────────────────────────
    elif action == "pending_iban":
        pays = await many("""
            SELECT ip.*, d.code, d.buyer_id, d.description
            FROM iban_pay ip JOIN deals d ON ip.deal_id=d.id
            WHERE ip.status='waiting' ORDER BY ip.created_at DESC
        """)
        if not pays:
            await call.message.answer("✅ Bekleyen IBAN ödemesi yok.")
        for p in pays:
            await call.message.answer(
                f"🏦 <b>IBAN Ödemesi</b>\n\n"
                f"Anlaşma: #{p['code']} | Alıcı: {p['buyer_id']}\n"
                f"Konu: {p['description']}\n"
                f"Tutar: <b>{p['amount']} {p['currency']}</b>\n"
                f"IBAN: {p['iban']}",
                reply_markup=ikb(
                    [("✅ Onayla", f"adm_iban_ok:{p['deal_id']}"),
                     ("❌ Reddet", f"adm_iban_no:{p['deal_id']}")]
                )
            )

    # ── KRİPTO BAKİYELER ─────────────────────────────────────────
    elif action == "balances":
        await call.message.answer("⏳ Sorgulaniyor...")
        addrs = await many("""
            SELECT ca.*, d.code FROM crypto_addr ca
            JOIN deals d ON ca.deal_id=d.id
            WHERE d.status NOT IN ('cancelled','released')
            ORDER BY ca.created_at DESC LIMIT 20
        """)
        if not addrs:
            await call.message.answer("💤 Aktif kripto adresi yok.")
        else:
            txt = "💎 <b>Kripto Bakiyeleri</b>\n\n"
            btns = []
            for a in addrs:
                bal = await get_balance(a["coin"], a["address"])
                txt += (f"#{a['code']} | {a['coin']}\n"
                        f"<code>{a['address'][:28]}...</code>\n"
                        f"Beklenen: {a['expected']} | Gerçek: {bal:.6f}\n"
                        f"Durum: {a['status']}\n──────\n")
                if bal > 0:
                    btns.append([(f"💸 #{a['code']} Gönder", f"adm_bal_send:{a['id']}")])
            await call.message.answer(txt, reply_markup=ikb(*btns) if btns else None)

    # ── FON GÖNDER ───────────────────────────────────────────────
    elif action == "send":
        addrs = await many("""
            SELECT ca.*, d.code FROM crypto_addr ca
            JOIN deals d ON ca.deal_id=d.id
            WHERE ca.received > 0 OR ca.status='received'
        """)
        if not addrs:
            await call.message.answer("💤 Gönderilecek bakiyeli adres yok.")
        else:
            btns = [[(f"#{a['code']} {a['coin']} ({a['received']})", f"adm_bal_send:{a['id']}")]
                    for a in addrs]
            await call.message.answer("💸 <b>Hangi adresten gönderim?</b>", reply_markup=ikb(*btns))

    # ── ANLAŞMALAR ───────────────────────────────────────────────
    elif action == "deals":
        await call.message.answer(
            "📊 <b>Anlaşma Filtresi:</b>",
            reply_markup=ikb(
                [("⏳ Bekleyen", "adm_dl:payment_pending"),
                 ("✅ Tamamlanan", "adm_dl:released")],
                [("❌ İptal", "adm_dl:cancelled"),
                 ("⚠️ Dispute", "adm_dl:disputed")],
                [("📋 Tümü", "adm_dl:all")]
            )
        )

    # ── DISPUTELAR ────────────────────────────────────────────────
    elif action == "disputes":
        deals = await many("SELECT * FROM deals WHERE status='disputed' ORDER BY created_at DESC")
        if not deals:
            await call.message.answer("✅ Açık dispute yok.")
        for d in deals:
            await call.message.answer(
                deal_text(d),
                reply_markup=ikb(
                    [("✅ Alıcı Haklı", f"adm_dis_buyer:{d['id']}"),
                     ("✅ Satıcı Haklı", f"adm_dis_seller:{d['id']}")]
                )
            )

    # ── İSTATİSTİKLER ─────────────────────────────────────────────
    elif action == "stats":
        total    = await one("SELECT COUNT(*) c FROM deals")
        released = await one("SELECT COUNT(*) c FROM deals WHERE status='released'")
        vol      = await one("SELECT COALESCE(SUM(amount),0) s FROM deals WHERE status='released'")
        users    = await one("SELECT COUNT(*) c FROM users")
        pending  = await one("SELECT COUNT(*) c FROM deals WHERE status='payment_pending'")
        await call.message.answer(
            f"📈 <b>İstatistikler</b>\n\n"
            f"👥 Kullanıcı: {users['c']}\n"
            f"📋 Toplam Anlaşma: {total['c']}\n"
            f"⏳ Bekleyen: {pending['c']}\n"
            f"✅ Tamamlanan: {released['c']}\n"
            f"💰 Toplam Hacim: {vol['s']:.2f}"
        )

    # ── DUYURU ─────────────────────────────────────────────────────
    elif action == "broadcast":
        await state.set_state(Adm.broadcast)
        await call.message.answer("📢 Tüm kullanıcılara gönderilecek mesajı yazın:",
                                  reply_markup=CANCEL_KB)

    # ── KULLANICILAR ──────────────────────────────────────────────
    elif action == "users":
        users = await many("SELECT * FROM users ORDER BY created_at DESC LIMIT 20")
        txt = "👥 <b>Son Kullanıcılar</b>\n\n"
        btns = []
        for u in users:
            st = "🚫" if u["is_banned"] else "✅"
            txt += f"{st} {u['full_name'] or 'İsimsiz'} | <code>{u['user_id']}</code>\n"
            if u["is_banned"]:
                btns.append([(f"🔓 {u['user_id']} Yasağı Kaldır", f"adm_unban:{u['user_id']}")])
            else:
                btns.append([(f"🚫 {u['user_id']} Yasakla", f"adm_ban:{u['user_id']}")])
        await call.message.answer(txt, reply_markup=ikb(*btns) if btns else None)

    await call.answer()

# ── IBAN FSM ─────────────────────────────────────────────────────

@admin_r.message(StateFilter(Adm.iban_val))
async def adm_iban_val(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id)); return
    iban = msg.text.strip().replace(" ", "")
    if not (iban.upper().startswith("TR") and len(iban) == 26):
        await msg.answer("❌ Geçersiz IBAN! TR ile başlayan 26 karakter:"); return
    await state.update_data(iban=iban.upper())
    await state.set_state(Adm.iban_bank)
    await msg.answer("🏦 Banka adını girin:")

@admin_r.message(StateFilter(Adm.iban_bank))
async def adm_iban_bank(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    await state.update_data(bank=msg.text.strip())
    await state.set_state(Adm.iban_holder)
    await msg.answer("👤 Hesap sahibinin adını girin:")

@admin_r.message(StateFilter(Adm.iban_holder))
async def adm_iban_holder(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    data = await state.get_data()
    await state.clear()
    ii = {"iban": data["iban"], "bank": data["bank"], "holder": msg.text.strip()}
    await cfg_set("iban_info", ii)
    await msg.answer(
        f"✅ <b>IBAN Kaydedildi!</b>\n\n"
        f"IBAN: <code>{ii['iban']}</code>\n"
        f"Banka: {ii['bank']}\nSahip: {ii['holder']}",
        reply_markup=main_kb(msg.from_user.id)
    )

# ── IBAN ONAY/RED ────────────────────────────────────────────────

@admin_r.callback_query(F.data.startswith("adm_iban_ok:"))
async def adm_iban_ok(call: CallbackQuery, bot: Bot):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    did = int(call.data.split(":")[1])
    await exe("UPDATE iban_pay SET status='confirmed', admin_id=?, confirmed_at=? WHERE deal_id=?",
              (call.from_user.id, datetime.now().isoformat(), did))
    await exe("UPDATE deals SET status='confirmed' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    for uid in [d["buyer_id"], d["seller_id"]]:
        try:
            await bot.send_message(uid,
                f"✅ <b>Ödeme Onaylandı!</b>\n#{d['code']} — Alıcının teslim onayı bekleniyor.",
                reply_markup=ikb([("📋 Anlaşmayı Gör", f"detail:{did}")])
            )
        except: pass
    try: await call.message.edit_text("✅ IBAN ödemesi onaylandı!")
    except: await call.message.answer("✅ Onaylandı!")
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_iban_no:"))
async def adm_iban_no(call: CallbackQuery, bot: Bot):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    did = int(call.data.split(":")[1])
    await exe("UPDATE iban_pay SET status='rejected' WHERE deal_id=?", (did,))
    await exe("UPDATE deals SET status='cancelled' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    for uid in [d["buyer_id"], d["seller_id"]]:
        try: await bot.send_message(uid, f"❌ Anlaşma #{d['code']} IBAN ödemesi reddedildi.")
        except: pass
    try: await call.message.edit_text("❌ Reddedildi.")
    except: pass
    await call.answer()

# ── ANLAŞMA LİSTESİ ──────────────────────────────────────────────

@admin_r.callback_query(F.data.startswith("adm_dl:"))
async def adm_deal_list(call: CallbackQuery):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    status = call.data.split(":")[1]
    if status == "all":
        deals = await many("SELECT * FROM deals ORDER BY created_at DESC LIMIT 15")
    else:
        deals = await many("SELECT * FROM deals WHERE status=? ORDER BY created_at DESC LIMIT 15",
                           (status,))
    if not deals:
        await call.message.answer("📭 Bu durumda anlaşma yok.")
    for d in deals:
        btns = [[("🔍 Yönet", f"adm_mgmt:{d['id']}")]]
        await call.message.answer(deal_text(d), reply_markup=ikb(*btns))
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_mgmt:"))
async def adm_mgmt(call: CallbackQuery):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    did = int(call.data.split(":")[1])
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d: await call.answer("Bulunamadı", show_alert=True); return
    btns = []
    if d["status"] not in ("released","cancelled"):
        btns.append([("❌ İptal Et", f"adm_cancel:{did}")])
    if d["status"] in ("confirmed","payment_pending","paid"):
        btns.append([("💸 Serbest Bırak", f"adm_force_release:{did}")])
    await call.message.answer(deal_text(d), reply_markup=ikb(*btns) if btns else None)
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_cancel:"))
async def adm_cancel(call: CallbackQuery, bot: Bot):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    did = int(call.data.split(":")[1])
    await exe("UPDATE deals SET status='cancelled' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    for uid in [d["buyer_id"], d["seller_id"]]:
        try: await bot.send_message(uid, f"❌ Anlaşma #{d['code']} admin tarafından iptal edildi.")
        except: pass
    try: await call.message.edit_text("❌ İptal edildi.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_force_release:"))
async def adm_force_release(call: CallbackQuery, bot: Bot):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    did = int(call.data.split(":")[1])
    await exe("UPDATE deals SET status='released' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    for uid in [d["buyer_id"], d["seller_id"]]:
        try: await bot.send_message(uid, f"💸 Anlaşma #{d['code']} admin tarafından serbest bırakıldı.")
        except: pass
    try: await call.message.edit_text("✅ Serbest bırakıldı.")
    except: pass
    await call.answer()

# ── DISPUTE ÇÖZÜM ──────────────────────────────────────────────

@admin_r.callback_query(F.data.startswith("adm_dis_buyer:"))
async def adm_dis_buyer(call: CallbackQuery, bot: Bot):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    did = int(call.data.split(":")[1])
    await exe("UPDATE deals SET status='cancelled' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    msgs = {d["buyer_id"]: "✅ Dispute: Haklı bulundunuz, anlaşma iptal.",
            d["seller_id"]: "⚠️ Dispute: Alıcı haklı bulundu."}
    for uid, m in msgs.items():
        try: await bot.send_message(uid, m)
        except: pass
    try: await call.message.edit_text("✅ Alıcı lehine çözüldü.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_dis_seller:"))
async def adm_dis_seller(call: CallbackQuery, bot: Bot):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    did = int(call.data.split(":")[1])
    await exe("UPDATE deals SET status='released' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    msgs = {d["seller_id"]: "✅ Dispute: Haklı bulundunuz, ödeme aktarıldı.",
            d["buyer_id"]: "⚠️ Dispute: Satıcı haklı bulundu."}
    for uid, m in msgs.items():
        try: await bot.send_message(uid, m)
        except: pass
    try: await call.message.edit_text("✅ Satıcı lehine çözüldü.")
    except: pass
    await call.answer()

# ── ADMİN KRİPTO GÖNDER ─────────────────────────────────────────

@admin_r.callback_query(F.data.startswith("adm_bal_send:"))
async def adm_bal_send(call: CallbackQuery, state: FSMContext):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    aid = int(call.data.split(":")[1])
    ca = await one("SELECT * FROM crypto_addr WHERE id=?", (aid,))
    if not ca: await call.answer("Bulunamadı", show_alert=True); return
    await state.update_data(ca_id=aid, ca_coin=ca["coin"],
                            ca_addr=ca["address"], ca_priv=ca["privkey"])
    await state.set_state(Adm.send_to)
    await call.message.answer(
        f"💸 <b>Kripto Gönder</b>\n\nCoin: {ca['coin']}\n"
        f"Kaynak: <code>{ca['address']}</code>\n\n"
        f"Hedef adresi girin:",
        reply_markup=CANCEL_KB
    )
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_payout:"))
async def adm_payout(call: CallbackQuery, state: FSMContext):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    did = int(call.data.split(":")[1])
    ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (did,))
    if not ca: await call.answer("Bulunamadı", show_alert=True); return
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    net = round(d["amount"] - d["amount"] * FEE_PERCENT / 100, 6)
    await state.update_data(ca_id=ca["id"], ca_coin=ca["coin"],
                            ca_addr=ca["address"], ca_priv=ca["privkey"],
                            forced_amount=net)
    await state.set_state(Adm.send_to)
    await call.message.answer(
        f"💸 Satıcıya gönderim\nNet tutar: {net} {ca['coin']}\n\nSatıcı adresini girin:",
        reply_markup=CANCEL_KB
    )
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_iban_done:"))
async def adm_iban_done(call: CallbackQuery):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    try: await call.message.edit_text("✅ IBAN ödemesi gönderildi olarak işaretlendi.")
    except: pass
    await call.answer()

@admin_r.message(StateFilter(Adm.send_to))
async def adm_send_to(msg: Message, state: FSMContext):
    if not is_admin(msg.from_user.id): return
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id)); return
    await state.update_data(send_to=msg.text.strip())
    data = await state.get_data()
    if "forced_amount" in data:
        await state.set_state(Adm.send_amt)
        # forced amount ile devam
        await adm_do_send(msg, state)
    else:
        await state.set_state(Adm.send_amt)
        await msg.answer("💰 Gönderilecek miktarı girin:")

@admin_r.message(StateFilter(Adm.send_amt))
async def adm_send_amt(msg: Message, state: FSMContext, bot: Bot):
    if not is_admin(msg.from_user.id): return
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id)); return
    try: amount = float(msg.text.replace(",",".").strip())
    except:
        await msg.answer("❌ Geçersiz miktar."); return
    await state.update_data(send_amount=amount)
    await adm_do_send(msg, state)

async def adm_do_send(msg: Message, state: FSMContext):
    data = await state.get_data()
    if "send_amount" not in data and "forced_amount" not in data:
        return
    amount = data.get("send_amount") or data.get("forced_amount")
    await state.clear()
    await msg.answer(f"⏳ {amount} {data['ca_coin']} gönderiliyor...")
    tx = None
    if data["ca_coin"] in ("TRX","USDT_TRC20"):
        tx = await send_tron(data["ca_addr"], data["ca_priv"],
                             data["send_to"], amount, data["ca_coin"])
    elif data["ca_coin"] == "ETH":
        tx = await send_eth(data["ca_priv"], data["send_to"], amount)

    if tx:
        await msg.answer(
            f"✅ <b>Gönderim Başarılı!</b>\n\nTX: <code>{tx}</code>\n"
            f"Tutar: {amount} {data['ca_coin']}\nHedef: {data['send_to']}",
            reply_markup=main_kb(msg.from_user.id)
        )
        await exe(
            "INSERT INTO txlog(type,amount,currency,from_address,to_address,tx_hash,note) VALUES(?,?,?,?,?,?,?)",
            ("admin_send", amount, data["ca_coin"], data["ca_addr"],
             data["send_to"], tx, "Admin gönderim")
        )
    else:
        await msg.answer("❌ Gönderim başarısız! Kütüphane veya bakiye kontrol edin.",
                         reply_markup=main_kb(msg.from_user.id))

# ── DUYURU FSM ──────────────────────────────────────────────────

@admin_r.message(StateFilter(Adm.broadcast))
async def adm_broadcast(msg: Message, state: FSMContext, bot: Bot):
    if not is_admin(msg.from_user.id): return
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id)); return
    await state.clear()
    users = await many("SELECT user_id FROM users WHERE is_banned=0")
    ok = fail = 0
    for u in users:
        try:
            await bot.send_message(u["user_id"], f"📢 <b>Duyuru:</b>\n\n{msg.text}")
            ok += 1
        except: fail += 1
        await asyncio.sleep(0.05)
    await msg.answer(f"📢 Duyuru tamamlandı!\n✅ Gönderildi: {ok}\n❌ Başarısız: {fail}",
                     reply_markup=main_kb(msg.from_user.id))

# ── BAN/UNBAN ────────────────────────────────────────────────────

@admin_r.callback_query(F.data.startswith("adm_ban:"))
async def adm_ban(call: CallbackQuery):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    uid = int(call.data.split(":")[1])
    await exe("UPDATE users SET is_banned=1 WHERE user_id=?", (uid,))
    await call.answer(f"🚫 {uid} yasaklandı", show_alert=True)

@admin_r.callback_query(F.data.startswith("adm_unban:"))
async def adm_unban(call: CallbackQuery):
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    uid = int(call.data.split(":")[1])
    await exe("UPDATE users SET is_banned=0 WHERE user_id=?", (uid,))
    await call.answer(f"✅ {uid} yasağı kaldırıldı", show_alert=True)

# ════════════════════════════════════════════════════════
#  KRİPTO MONİTÖR (arka plan)
# ════════════════════════════════════════════════════════

async def crypto_monitor(bot: Bot):
    log.info("🔍 Kripto monitörü başladı")
    while True:
        try:
            addrs = await many("""
                SELECT ca.*, d.id as did, d.code, d.buyer_id, d.seller_id,
                       d.status as dst, d.amount as damount, d.currency as dcur, d.method
                FROM crypto_addr ca JOIN deals d ON ca.deal_id=d.id
                WHERE ca.status='waiting' AND d.status IN ('payment_pending','pending')
            """)
            for a in addrs:
                try:
                    bal = await get_balance(a["coin"], a["address"])
                    if bal >= float(a["expected"]) * 0.99:
                        await exe("UPDATE crypto_addr SET status='received', received=? WHERE id=?",
                                  (bal, a["id"]))
                        await exe("UPDATE deals SET status='confirmed' WHERE id=?", (a["did"],))
                        log.info(f"✅ Ödeme alındı #{a['code']} {bal} {a['coin']}")
                        for uid in [a["buyer_id"], a["seller_id"]]:
                            try:
                                await bot.send_message(uid,
                                    f"✅ <b>Kripto Ödeme Alındı!</b>\n\n"
                                    f"Anlaşma #{a['code']}\n"
                                    f"Alınan: <b>{bal} {a['coin']}</b>\n\n"
                                    f"{'Ürünü alınca onay verin.' if uid == a['buyer_id'] else 'Alıcı onayladıktan sonra ödeme gönderilecek.'}",
                                    reply_markup=ikb([("📋 Anlaşmaya Git", f"detail:{a['did']}")])
                                )
                            except Exception: pass
                    elif bal > 0:
                        await exe("UPDATE crypto_addr SET received=? WHERE id=?", (bal, a["id"]))
                except Exception as e:
                    log.warning(f"Adres kontrol hatası: {e}")
        except Exception as e:
            log.error(f"Monitor hatası: {e}")
        await asyncio.sleep(MONITOR_SEC)

# ════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════

async def main():
    await db_init()
    log.info("✅ Veritabanı hazır")

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode="HTML")
    )
    dp  = Dispatcher(storage=MemoryStorage())
    dp["bot"] = bot

    # Admin router önce kayıt edilmeli
    dp.include_router(admin_r)
    dp.include_router(user_r)

    asyncio.create_task(crypto_monitor(bot))

    log.info(f"🤖 Bot başlatıldı | Adminler: {ADMIN_IDS} | Komisyon: %{FEE_PERCENT}")
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())

if __name__ == "__main__":
    print("=== ESCROW BOT v2.0 BASLATILIYOR ===")
    print("1. BOT_TOKEN degiskenini ayarla")
    print("2. ADMIN_IDS listesine Telegram ID ekle")
    print("3. /admin komutu ile admin panele gir")
    print("=====================================")
    asyncio.run(main())
