#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Escrow + Wallet Bot v4.0
pip install aiogram==3.7.0 aiosqlite aiohttp tronpy eth-account web3
"""

import asyncio
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import aiohttp
import aiosqlite
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

# ═══════════════════════════════════════════════════════════
#  YAPILANDIRMA
# ═══════════════════════════════════════════════════════════
BOT_TOKEN     = os.getenv("BOT_TOKEN",      "8681267503:AAG7UUBdfVnyohkVTJr57Gn1Ke_qBEclTGY")
ADMIN_IDS     = [int(x) for x in os.getenv("ADMIN_IDS", "7672180974").split(",") if x.strip()]
DB_PATH       = os.getenv("DB_PATH",        "escrow.db")
FEE_PERCENT   = float(os.getenv("FEE_PERCENT",    "2.0"))
PAYMENT_HOURS = int(os.getenv("PAYMENT_HOURS",    "24"))
MONITOR_SEC   = int(os.getenv("MONITOR_SEC",      "30"))
TRON_API_KEY  = os.getenv("TRON_API_KEY",   "")

# Bot ana cüzdanı — tüm kullanıcı bakiyeleri burada toplanır
# Gerçek kullanımda bu değerleri env'den alın!
MASTER_TRX_ADDR = os.getenv("MASTER_TRX_ADDR", "TE8o7mf1Z92ELZzUS6dY57t4SvcCBCZbyB")   # Ana TRX/USDT cüzdan adresi
MASTER_TRX_KEY  = os.getenv("MASTER_TRX_KEY",  "")   # Ana TRX/USDT private key
MASTER_ETH_ADDR = os.getenv("MASTER_ETH_ADDR", "0xdc1949e9E6dBEDEd4Ccb03E92007B302638F6278")   # Ana ETH cüzdan adresi
MASTER_ETH_KEY  = os.getenv("MASTER_ETH_KEY",  "")   # Ana ETH private key
MASTER_BTC_ADDR = os.getenv("MASTER_BTC_ADDR", "")   # Ana BTC cüzdan adresi
# ═══════════════════════════════════════════════════════════

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
log = logging.getLogger("escrow")

USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

COINS: Dict[str, str] = {
    "USDT_TRC20": "💎 USDT (TRC20)",
    "TRX":        "⚡ TRX",
    "ETH":        "🔷 ETH",
    "BTC":        "₿ BTC",
}

STATUS_EMOJI = {
    "payment_pending": "💳",
    "confirmed":       "🔐",
    "released":        "💸",
    "cancelled":       "❌",
    "disputed":        "⚠️",
}

# ═══════════════════════════════════════════════════════════
#  VERİTABANI
# ═══════════════════════════════════════════════════════════

async def db_init() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id    INTEGER PRIMARY KEY,
            username   TEXT DEFAULT '',
            full_name  TEXT DEFAULT '',
            is_banned  INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );

        -- Kullanıcı bakiyeleri (her coin ayrı satır)
        CREATE TABLE IF NOT EXISTS balances (
            user_id INTEGER,
            coin    TEXT,
            amount  REAL DEFAULT 0,
            PRIMARY KEY (user_id, coin)
        );

        -- Bakiye yükleme için geçici adresler
        CREATE TABLE IF NOT EXISTS deposit_addr (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            coin       TEXT,
            address    TEXT UNIQUE,
            privkey    TEXT,
            expected   REAL DEFAULT 0,
            received   REAL DEFAULT 0,
            status     TEXT DEFAULT 'waiting',
            created_at TEXT DEFAULT (datetime('now'))
        );

        -- Cüzdan işlem geçmişi
        CREATE TABLE IF NOT EXISTS wallet_tx (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            type        TEXT,   -- deposit/withdraw/send/receive/escrow_in/escrow_out
            coin        TEXT,
            amount      REAL,
            fee         REAL DEFAULT 0,
            counterpart INTEGER,  -- karşı taraf user_id (send/receive için)
            tx_hash     TEXT,
            note        TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        -- Escrow anlaşmaları
        CREATE TABLE IF NOT EXISTS deals (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            code        TEXT UNIQUE,
            buyer_id    INTEGER,
            seller_id   INTEGER,
            creator_id  INTEGER,
            amount      REAL,
            currency    TEXT DEFAULT 'TRY',
            description TEXT,
            method      TEXT,
            status      TEXT DEFAULT 'payment_pending',
            deadline    TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        -- Kripto escrow adresleri
        CREATE TABLE IF NOT EXISTS crypto_addr (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_id    INTEGER,
            coin       TEXT,
            address    TEXT UNIQUE,
            privkey    TEXT,
            expected   REAL,
            received   REAL DEFAULT 0,
            status     TEXT DEFAULT 'waiting',
            tx_hash    TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        -- IBAN escrow kayıtları
        CREATE TABLE IF NOT EXISTS iban_pay (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_id      INTEGER,
            iban         TEXT, bank TEXT, holder TEXT,
            amount       REAL, currency TEXT,
            status       TEXT DEFAULT 'waiting',
            admin_id     INTEGER, confirmed_at TEXT,
            created_at   TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS txlog (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_id      INTEGER, type TEXT,
            amount REAL, currency TEXT,
            from_address TEXT, to_address TEXT,
            tx_hash TEXT, note TEXT,
            created_at   TEXT DEFAULT (datetime('now'))
        );
        """)
        await db.commit()


async def cfg_get(key: str, default=None):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT value FROM settings WHERE key=?", (key,)) as c:
            row = await c.fetchone()
            if row:
                try: return json.loads(row[0])
                except: return row[0]
            return default

async def cfg_set(key: str, value) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, json.dumps(value)))
        await db.commit()

async def cfg_del(key: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM settings WHERE key=?", (key,))
        await db.commit()

async def one(q: str, p: tuple = ()) -> Optional[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(q, p) as c:
            row = await c.fetchone()
            return dict(row) if row else None

async def many(q: str, p: tuple = ()) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(q, p) as c:
            return [dict(r) for r in await c.fetchall()]

async def exe(q: str, p: tuple = ()) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(q, p)
        await db.commit()
        return cur.lastrowid

# ═══════════════════════════════════════════════════════════
#  BAKİYE YARDIMCILARI
# ═══════════════════════════════════════════════════════════

async def get_balance(user_id: int, coin: str) -> float:
    row = await one("SELECT amount FROM balances WHERE user_id=? AND coin=?", (user_id, coin))
    return row["amount"] if row else 0.0

async def add_balance(user_id: int, coin: str, amount: float) -> float:
    await exe("""
        INSERT INTO balances(user_id, coin, amount) VALUES(?,?,?)
        ON CONFLICT(user_id, coin) DO UPDATE SET amount = amount + ?
    """, (user_id, coin, amount, amount))
    return await get_balance(user_id, coin)

async def sub_balance(user_id: int, coin: str, amount: float) -> bool:
    """Bakiye düşür. Yetersizse False döner."""
    bal = await get_balance(user_id, coin)
    if bal < amount:
        return False
    await exe("""
        UPDATE balances SET amount = amount - ? WHERE user_id=? AND coin=?
    """, (amount, user_id, coin))
    return True

async def all_balances(user_id: int) -> Dict[str, float]:
    rows = await many("SELECT coin, amount FROM balances WHERE user_id=? AND amount > 0", (user_id,))
    return {r["coin"]: r["amount"] for r in rows}

async def log_wallet_tx(user_id: int, type_: str, coin: str, amount: float,
                         fee: float = 0, counterpart: int = None,
                         tx_hash: str = None, note: str = None) -> None:
    await exe(
        "INSERT INTO wallet_tx(user_id,type,coin,amount,fee,counterpart,tx_hash,note) VALUES(?,?,?,?,?,?,?,?)",
        (user_id, type_, coin, amount, fee, counterpart, tx_hash, note)
    )

# ═══════════════════════════════════════════════════════════
#  CÜZDAN ÜRETİCİ
# ═══════════════════════════════════════════════════════════

def gen_tron() -> Tuple[str, str]:
    try:
        from tronpy.keys import PrivateKey
        pk = PrivateKey(secrets.token_bytes(32))
        return pk.public_key.to_base58check_address(), pk.hex()
    except Exception:
        priv  = secrets.token_hex(32)
        raw   = hashlib.sha256(bytes.fromhex(priv)).digest()
        chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        addr  = "T" + "".join(chars[b % 58] for b in raw[:33])
        return addr, priv

def gen_eth() -> Tuple[str, str]:
    try:
        from eth_account import Account
        a = Account.create(extra_entropy=secrets.token_hex(32))
        return a.address, a.key.hex()
    except Exception:
        priv = "0x" + secrets.token_hex(32)
        h    = hashlib.sha256(priv.encode()).hexdigest()
        return "0x" + h[:40], priv

def gen_btc() -> Tuple[str, str]:
    priv  = secrets.token_hex(32)
    raw   = hashlib.sha256(bytes.fromhex(priv)).digest()
    chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    addr  = "1" + "".join(chars[b % 58] for b in raw[:33])
    return addr, priv

def make_addr(coin: str) -> Tuple[str, str]:
    c = coin.upper()
    if c in ("TRX", "USDT_TRC20"): return gen_tron()
    if c == "ETH":                  return gen_eth()
    if c == "BTC":                  return gen_btc()
    raise ValueError(f"Bilinmeyen coin: {coin}")

# ═══════════════════════════════════════════════════════════
#  BLOCKCHAIN BAKIYE SORGULAMA
# ═══════════════════════════════════════════════════════════

async def _get(url: str, headers: dict = None) -> dict:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, headers=headers or {}, timeout=aiohttp.ClientTimeout(total=12)) as r:
                return await r.json(content_type=None)
    except Exception as e:
        log.warning("HTTP %s: %s", url, e)
        return {}

async def chain_bal_trx(addr: str) -> float:
    h = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}
    d = await _get(f"https://api.trongrid.io/v1/accounts/{addr}", h)
    return d.get("data", [{}])[0].get("balance", 0) / 1_000_000

async def chain_bal_usdt(addr: str) -> float:
    h = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}
    d = await _get(f"https://api.trongrid.io/v1/accounts/{addr}/tokens", h)
    for t in d.get("data", []):
        if t.get("tokenId") == USDT_CONTRACT or t.get("tokenAbbr") == "USDT":
            return float(t.get("balance", 0)) / 1_000_000
    return 0.0

async def chain_bal_eth(addr: str) -> float:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post("https://cloudflare-eth.com",
                              json={"jsonrpc":"2.0","method":"eth_getBalance","params":[addr,"latest"],"id":1},
                              timeout=aiohttp.ClientTimeout(total=12)) as r:
                d = await r.json()
                return int(d.get("result","0x0"), 16) / 1e18
    except: return 0.0

async def chain_bal_btc(addr: str) -> float:
    d  = await _get(f"https://blockstream.info/api/address/{addr}")
    cs = d.get("chain_stats", {})
    return (cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)) / 1e8

async def chain_balance(coin: str, addr: str) -> float:
    c = coin.upper()
    if c == "TRX":         return await chain_bal_trx(addr)
    if c == "USDT_TRC20":  return await chain_bal_usdt(addr)
    if c == "ETH":         return await chain_bal_eth(addr)
    if c == "BTC":         return await chain_bal_btc(addr)
    return 0.0

# ═══════════════════════════════════════════════════════════
#  KRİPTO GÖNDERME
# ═══════════════════════════════════════════════════════════

async def send_tron(from_addr: str, privkey: str, to_addr: str, amount: float, coin: str) -> Optional[str]:
    try:
        from tronpy import Tron
        from tronpy.keys import PrivateKey
        from tronpy.providers import HTTPProvider
        provider = HTTPProvider(api_key=TRON_API_KEY) if TRON_API_KEY else None
        client   = Tron(provider=provider)
        pk       = PrivateKey(bytes.fromhex(privkey))
        if coin == "TRX":
            txn = client.trx.transfer(from_addr, to_addr, int(amount * 1_000_000)).memo("Escrow").build().sign(pk)
        else:
            contract = client.get_contract(USDT_CONTRACT)
            txn = contract.functions.transfer(to_addr, int(amount * 1_000_000)).with_owner(from_addr).fee_limit(20_000_000).build().sign(pk)
        res = txn.broadcast().wait()
        return res.get("id") or res.get("txid")
    except Exception as e:
        log.error("Tron send: %s", e)
        return None

async def send_eth(privkey: str, to_addr: str, amount: float) -> Optional[str]:
    try:
        from eth_account import Account
        from web3 import Web3
        w3   = Web3(Web3.HTTPProvider("https://cloudflare-eth.com"))
        acct = Account.from_key(privkey)
        tx   = {"to": to_addr, "value": w3.to_wei(amount, "ether"), "gas": 21000,
                "gasPrice": w3.eth.gas_price, "nonce": w3.eth.get_transaction_count(acct.address), "chainId": 1}
        signed = acct.sign_transaction(tx)
        return w3.eth.send_raw_transaction(signed.rawTransaction).hex()
    except Exception as e:
        log.error("ETH send: %s", e)
        return None

async def send_crypto(coin: str, from_addr: str, privkey: str, to_addr: str, amount: float) -> Optional[str]:
    if coin in ("TRX", "USDT_TRC20"):
        return await send_tron(from_addr, privkey, to_addr, amount, coin)
    if coin == "ETH":
        return await send_eth(privkey, to_addr, amount)
    return None  # BTC manuel

# master cüzdandan gönder
async def master_send(coin: str, to_addr: str, amount: float) -> Optional[str]:
    if coin in ("TRX", "USDT_TRC20"):
        return await send_crypto(coin, MASTER_TRX_ADDR, MASTER_TRX_KEY, to_addr, amount)
    if coin == "ETH":
        return await send_eth(MASTER_ETH_KEY, to_addr, amount)
    return None

# ═══════════════════════════════════════════════════════════
#  YARDIMCILAR
# ═══════════════════════════════════════════════════════════

def gen_code() -> str:
    return secrets.token_hex(4).upper()

def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS

def is_group(msg: Message) -> bool:
    return msg.chat.type in ("group", "supergroup")

def ikb(*rows) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t, callback_data=cb) for t, cb in row]
        for row in rows
    ])

def deal_text(d: Dict) -> str:
    e = STATUS_EMOJI.get(d["status"], "❓")
    return (f"{e} <b>Anlaşma #{d['code']}</b>\n"
            f"💰 {d['amount']} {d['currency']}\n"
            f"📦 {d['description']}\n"
            f"💳 {d.get('method','—')}\n"
            f"📊 <b>{d['status']}</b> | {d['created_at'][:16]}")

def fmt_bal(bals: Dict[str, float]) -> str:
    if not bals:
        return "Bakiye yok"
    return "\n".join(f"  {COINS.get(c, c)}: <b>{v:.6f}</b>" for c, v in bals.items())

async def ensure_user(user) -> None:
    await exe("INSERT OR REPLACE INTO users(user_id,username,full_name) VALUES(?,?,?)",
              (user.id, user.username or "", user.full_name or ""))

# ═══════════════════════════════════════════════════════════
#  FSM STATES
# ═══════════════════════════════════════════════════════════

class DealFSM(StatesGroup):
    partner  = State()
    role     = State()
    amount   = State()
    currency = State()
    desc     = State()
    method   = State()
    confirm  = State()

class WithdrawFSM(StatesGroup):
    coin    = State()
    amount  = State()
    address = State()
    confirm = State()

class SendFSM(StatesGroup):
    target  = State()
    coin    = State()
    amount  = State()
    confirm = State()

class AdminFSM(StatesGroup):
    iban_val    = State()
    iban_bank   = State()
    iban_holder = State()
    send_to     = State()
    send_amt    = State()
    broadcast   = State()

# ═══════════════════════════════════════════════════════════
#  ROUTERLAR
# ═══════════════════════════════════════════════════════════

user_r  = Router()
admin_r = Router()

# ═══════════════════════════════════════════════════════════
#  /start  &  /yardim
# ═══════════════════════════════════════════════════════════

@user_r.message(CommandStart())
async def cmd_start(msg: Message, state: FSMContext) -> None:
    await state.clear()
    await ensure_user(msg.from_user)
    u = await one("SELECT is_banned FROM users WHERE user_id=?", (msg.from_user.id,))
    if u and u["is_banned"]:
        await msg.answer("🚫 Hesabınız yasaklandı.")
        return
    await msg.answer(
        "🔐 <b>Escrow & Wallet Bot</b>\n\n"
        "📋 <b>Komutlar:</b>\n"
        "/ticaret — Güvenli escrow anlaşması oluştur\n"
        "/tic — /ticaret kısayolu\n\n"
        "💰 <b>Cüzdan:</b>\n"
        "/bakiye — Bakiyeni görüntüle\n"
        "/yukle — Kripto bakiye yükle\n"
        "/cek — Kripto çek\n"
        "/gonder @kullanici miktar coin — Kullanıcıya gönder\n"
        "/send @kullanici miktar coin — /gonder kısayolu\n\n"
        "👥 <b>Grup:</b>\n"
        "Grup sohbetlerinde /ticaret ve /send komutları çalışır\n\n"
        f"💸 Komisyon: %{FEE_PERCENT} | ⏰ Ödeme süresi: {PAYMENT_HOURS}s"
    )

@user_r.message(Command("yardim", "help"))
async def cmd_help(msg: Message) -> None:
    await msg.answer(
        "📋 <b>Tüm Komutlar</b>\n\n"
        "<b>Escrow:</b>\n"
        "/ticaret — Yeni anlaşma oluştur\n"
        "/tic — Kısayol\n"
        "/anlasmalarim — Anlaşmalarını listele\n\n"
        "<b>Cüzdan (sadece DM):</b>\n"
        "/bakiye — Bakiyeni gör\n"
        "/yukle — Kripto yükle\n"
        "/cek — Kripto çek\n\n"
        "<b>Transfer (DM ve Grup):</b>\n"
        "/gonder @kullanici miktar COIN\n"
        "/send @kullanici miktar COIN\n"
        "<i>Örnek: /send @ahmet 10 USDT_TRC20</i>\n\n"
        "<b>Admin:</b>\n"
        "/admin — Admin paneli"
    )

# ═══════════════════════════════════════════════════════════
#  /bakiye
# ═══════════════════════════════════════════════════════════

@user_r.message(Command("bakiye", "balance"))
async def cmd_bakiye(msg: Message) -> None:
    if is_group(msg):
        await msg.answer("⚠️ Bakiye bilgisi gizlilik için sadece DM'de görüntülenir.")
        return
    await ensure_user(msg.from_user)
    uid  = msg.from_user.id
    bals = await all_balances(uid)

    # Son 5 işlem
    txs = await many(
        "SELECT * FROM wallet_tx WHERE user_id=? ORDER BY created_at DESC LIMIT 5",
        (uid,)
    )
    tx_txt = ""
    if txs:
        tx_txt = "\n\n📜 <b>Son İşlemler:</b>\n"
        for t in txs:
            sign  = "+" if t["type"] in ("deposit","receive","escrow_out") else "-"
            emoji = {"deposit":"📥","withdraw":"📤","send":"➡️","receive":"⬅️",
                     "escrow_in":"🔐","escrow_out":"💸"}.get(t["type"], "🔄")
            tx_txt += f"{emoji} {sign}{t['amount']:.6f} {t['coin']} | {t['created_at'][:16]}\n"

    await msg.answer(
        f"💰 <b>Cüzdanınız</b>\n\n"
        f"{fmt_bal(bals)}"
        f"{tx_txt}\n\n"
        f"📥 /yukle — Kripto yükle\n"
        f"📤 /cek — Kripto çek",
        reply_markup=ikb(
            [("📥 Bakiye Yükle", "wallet:deposit"), ("📤 Çekim Yap", "wallet:withdraw")],
            [("📜 Tüm Geçmiş",   "wallet:history")]
        )
    )

# ═══════════════════════════════════════════════════════════
#  /yukle — Bakiye yükleme
# ═══════════════════════════════════════════════════════════

@user_r.message(Command("yukle", "deposit"))
async def cmd_yukle(msg: Message) -> None:
    if is_group(msg):
        await msg.answer("⚠️ Bakiye yükleme sadece DM'de yapılır.")
        return
    await ensure_user(msg.from_user)
    await msg.answer(
        "📥 <b>Bakiye Yükle</b>\n\nHangi kripto ile yüklemek istiyorsunuz?",
        reply_markup=ikb(
            [("💎 USDT TRC20", "dep:USDT_TRC20"), ("⚡ TRX", "dep:TRX")],
            [("🔷 ETH",         "dep:ETH"),        ("₿ BTC",  "dep:BTC")]
        )
    )

@user_r.callback_query(F.data.startswith("dep:"))
async def dep_coin_select(call: CallbackQuery) -> None:
    if is_group(call.message):
        await call.answer("Sadece DM'de kullanılır.", show_alert=True)
        return
    coin = call.data.split(":")[1]
    uid  = call.from_user.id

    # Mevcut aktif deposit adresi var mı?
    existing = await one(
        "SELECT * FROM deposit_addr WHERE user_id=? AND coin=? AND status='waiting'",
        (uid, coin)
    )
    if existing:
        addr = existing["address"]
    else:
        addr, privkey = make_addr(coin)
        await exe(
            "INSERT INTO deposit_addr(user_id,coin,address,privkey) VALUES(?,?,?,?)",
            (uid, coin, addr, privkey)
        )

    await call.message.edit_text(
        f"📥 <b>{COINS.get(coin, coin)} Yükleme Adresi</b>\n\n"
        f"<code>{addr}</code>\n\n"
        f"✅ Bu adrese gönderin — bakiyeniz otomatik yüklenir.\n"
        f"🔄 Kontrol sıklığı: {MONITOR_SEC} saniye\n\n"
        f"⚠️ Sadece <b>{coin}</b> gönderin!"
    )
    await call.answer()

@user_r.callback_query(F.data == "wallet:deposit")
async def wallet_deposit_btn(call: CallbackQuery) -> None:
    await cmd_yukle(call.message)
    await call.answer()

# ═══════════════════════════════════════════════════════════
#  /cek — Bakiye çekme
# ═══════════════════════════════════════════════════════════

@user_r.message(Command("cek", "withdraw"))
async def cmd_cek(msg: Message, state: FSMContext) -> None:
    if is_group(msg):
        await msg.answer("⚠️ Çekim sadece DM'de yapılır.")
        return
    await ensure_user(msg.from_user)
    uid  = msg.from_user.id
    bals = await all_balances(uid)
    if not bals:
        await msg.answer("💸 Çekilecek bakiyeniz yok. Önce /yukle ile yükleyin.")
        return
    await state.set_state(WithdrawFSM.coin)
    btns = [(f"{COINS.get(c,c)} ({v:.4f})", f"wd_coin:{c}") for c, v in bals.items()]
    rows = [btns[i:i+2] for i in range(0, len(btns), 2)]
    await msg.answer(
        "📤 <b>Çekim Yap</b>\n\nHangi coini çekmek istiyorsunuz?",
        reply_markup=ikb(*rows)
    )

@user_r.callback_query(F.data.startswith("wd_coin:"), StateFilter(WithdrawFSM.coin))
async def wd_coin(call: CallbackQuery, state: FSMContext) -> None:
    coin = call.data.split(":")[1]
    uid  = call.from_user.id
    bal  = await get_balance(uid, coin)
    await state.update_data(coin=coin, bal=bal)
    await state.set_state(WithdrawFSM.amount)
    await call.message.edit_text(
        f"📤 <b>Çekim — {COINS.get(coin, coin)}</b>\n\n"
        f"Mevcut bakiye: <b>{bal:.6f} {coin}</b>\n\n"
        f"Çekmek istediğiniz miktarı yazın:\n"
        f"<i>Tümünü çekmek için: all</i>"
    )
    await call.answer()

@user_r.message(StateFilter(WithdrawFSM.amount))
async def wd_amount(msg: Message, state: FSMContext) -> None:
    data = await state.get_data()
    bal  = data["bal"]
    text = msg.text.strip().lower()
    if text == "iptal":
        await state.clear()
        await msg.answer("❌ İptal edildi.")
        return
    if text == "all":
        amount = bal
    else:
        try:
            amount = float(text.replace(",", "."))
            if amount <= 0 or amount > bal:
                raise ValueError
        except ValueError:
            await msg.answer(f"❌ Geçersiz miktar. Maks: {bal:.6f}\n<i>İptal için: iptal</i>")
            return
    await state.update_data(amount=amount)
    await state.set_state(WithdrawFSM.address)
    await msg.answer(
        f"📤 Miktar: <b>{amount:.6f} {data['coin']}</b>\n\n"
        f"Göndereceğiniz <b>{data['coin']}</b> adresini girin:"
    )

@user_r.message(StateFilter(WithdrawFSM.address))
async def wd_address(msg: Message, state: FSMContext) -> None:
    data = await state.get_data()
    addr = msg.text.strip()
    coin = data["coin"]
    if msg.text.strip().lower() == "iptal":
        await state.clear()
        await msg.answer("❌ İptal edildi.")
        return
    valid = (
        (coin in ("TRX","USDT_TRC20") and addr.startswith("T") and len(addr) == 34) or
        (coin == "ETH"                and addr.startswith("0x") and len(addr) == 42) or
        (coin == "BTC"                and (addr.startswith("1") or addr.startswith("3") or addr.startswith("bc1")))
    )
    if not valid:
        await msg.answer(f"❌ Geçersiz {coin} adresi. Tekrar girin:")
        return
    await state.update_data(address=addr)
    await state.set_state(WithdrawFSM.confirm)
    fee = round(data["amount"] * 0.005, 6)  # %0.5 çekim ücreti
    net = round(data["amount"] - fee, 6)
    await msg.answer(
        f"📤 <b>Çekim Onayı</b>\n\n"
        f"Coin: <b>{COINS.get(coin, coin)}</b>\n"
        f"Miktar: <b>{data['amount']:.6f}</b>\n"
        f"İşlem ücreti (%0.5): <b>{fee:.6f}</b>\n"
        f"Net gönderilecek: <b>{net:.6f}</b>\n"
        f"Adres: <code>{addr}</code>\n\n"
        f"Onaylıyor musunuz?",
        reply_markup=ikb(
            [("✅ Onayla", "wd_confirm:yes")],
            [("❌ İptal",   "wd_confirm:no")]
        )
    )

@user_r.callback_query(F.data.startswith("wd_confirm:"), StateFilter(WithdrawFSM.confirm))
async def wd_confirm(call: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    if call.data == "wd_confirm:no":
        await state.clear()
        await call.message.edit_text("❌ İptal edildi.")
        await call.answer()
        return

    data   = await state.get_data()
    await state.clear()
    uid    = call.from_user.id
    coin   = data["coin"]
    amount = data["amount"]
    addr   = data["address"]
    fee    = round(amount * 0.005, 6)
    net    = round(amount - fee, 6)

    # Bakiye düş
    ok = await sub_balance(uid, coin, amount)
    if not ok:
        await call.message.edit_text("❌ Yetersiz bakiye.")
        await call.answer()
        return

    await call.message.edit_text(f"⏳ <b>{net:.6f} {coin}</b> gönderiliyor...")
    await call.answer()

    # Master cüzdandan gönder
    tx = await master_send(coin, addr, net)
    if tx:
        await log_wallet_tx(uid, "withdraw", coin, amount, fee=fee, tx_hash=tx,
                            note=f"→ {addr}")
        await call.message.answer(
            f"✅ <b>Çekim Başarılı!</b>\n\n"
            f"💰 Gönderilen: <b>{net:.6f} {coin}</b>\n"
            f"📬 Adres: <code>{addr}</code>\n"
            f"🔗 TX: <code>{tx}</code>"
        )
    else:
        # Gönderim başarısız — bakiyeyi geri yükle
        await add_balance(uid, coin, amount)
        await call.message.answer(
            "❌ Otomatik gönderim başarısız.\n"
            "Admin ile iletişime geçin, bakiyeniz iade edildi."
        )
        for aid in ADMIN_IDS:
            try:
                await bot.send_message(
                    aid,
                    f"🚨 <b>Çekim BAŞARISIZ</b>\n"
                    f"Kullanıcı: <code>{uid}</code>\n"
                    f"Coin: {coin} | Net: {net:.6f}\n"
                    f"Adres: <code>{addr}</code>",
                    reply_markup=ikb([("💸 Manuel Gönder", f"adm_manual_wd:{uid}:{coin}:{net}:{addr}")])
                )
            except Exception:
                pass

@user_r.callback_query(F.data == "wallet:withdraw")
async def wallet_wd_btn(call: CallbackQuery, state: FSMContext) -> None:
    await cmd_cek(call.message, state)
    await call.answer()

@user_r.callback_query(F.data == "wallet:history")
async def wallet_history(call: CallbackQuery) -> None:
    uid = call.from_user.id
    txs = await many(
        "SELECT * FROM wallet_tx WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
        (uid,)
    )
    if not txs:
        await call.message.edit_text("📜 İşlem geçmişi boş.")
        await call.answer()
        return
    txt = "📜 <b>Son 20 İşlem</b>\n\n"
    for t in txs:
        sign  = "+" if t["type"] in ("deposit","receive","escrow_out") else "-"
        emoji = {"deposit":"📥","withdraw":"📤","send":"➡️","receive":"⬅️",
                 "escrow_in":"🔐","escrow_out":"💸"}.get(t["type"],"🔄")
        txt += f"{emoji} {sign}{t['amount']:.6f} {t['coin']} | {t['type']} | {t['created_at'][:16]}\n"
    await call.message.edit_text(txt)
    await call.answer()

# ═══════════════════════════════════════════════════════════
#  /send veya /gonder — Kullanıcıya kripto gönder
#  Kullanım: /send @kullanici 10 USDT_TRC20
#            /send (sadece komut → FSM başlatır)
# ═══════════════════════════════════════════════════════════

@user_r.message(Command("send", "gonder"))
async def cmd_send(msg: Message, state: FSMContext) -> None:
    await ensure_user(msg.from_user)
    uid = msg.from_user.id
    u   = await one("SELECT is_banned FROM users WHERE user_id=?", (uid,))
    if u and u["is_banned"]:
        await msg.answer("🚫 Hesabınız yasaklandı.")
        return

    # Argümanları parse et: /send @kullanici miktar COIN
    args = msg.text.split()[1:] if msg.text else []
    mention = msg.entities and next(
        (e for e in msg.entities if e.type in ("mention", "text_mention")), None
    )

    target_id   = None
    target_name = None

    # mention entity varsa kullan
    if mention:
        if mention.type == "text_mention":
            target_id   = mention.user.id
            target_name = mention.user.full_name
        elif mention.type == "mention":
            uname = msg.text[mention.offset+1:mention.offset+mention.length]
            row   = await one("SELECT user_id, full_name FROM users WHERE username=?", (uname,))
            if row:
                target_id   = row["user_id"]
                target_name = row["full_name"] or uname

    # Hızlı komut: /send @ali 10 USDT_TRC20
    amount = None
    coin   = None
    for a in args:
        try:
            amount = float(a.replace(",","."))
        except ValueError:
            if a.upper() in COINS and not a.startswith("@"):
                coin = a.upper()

    if target_id and amount and coin:
        # Direkt gönder
        await _do_send(msg, uid, target_id, target_name or str(target_id), coin, amount)
        return

    # FSM başlat
    await state.set_state(SendFSM.target)
    if target_id:
        await state.update_data(target_id=target_id, target_name=target_name or str(target_id))
        await state.set_state(SendFSM.coin)
        bals = await all_balances(uid)
        if not bals:
            await state.clear()
            await msg.answer("💸 Bakiyeniz yok. Önce /yukle ile yükleyin.")
            return
        btns = [(f"{COINS.get(c,c)} ({v:.4f})", f"snd_coin:{c}") for c, v in bals.items()]
        rows = [btns[i:i+2] for i in range(0, len(btns), 2)]
        await msg.answer(
            f"➡️ <b>Gönder</b> — Alıcı: <b>{target_name or target_id}</b>\n\n"
            f"Hangi coini göndermek istiyorsunuz?",
            reply_markup=ikb(*rows)
        )
    else:
        await msg.answer(
            "➡️ <b>Kripto Gönder</b>\n\n"
            "Kime göndermek istiyorsunuz?\n"
            "Kullanıcıyı <b>etiketleyin</b> ya da <b>Telegram ID</b> yazın:\n"
            "<i>İptal için: iptal</i>"
        )

@user_r.message(StateFilter(SendFSM.target))
async def snd_target(msg: Message, state: FSMContext) -> None:
    if msg.text.strip().lower() == "iptal":
        await state.clear()
        await msg.answer("❌ İptal edildi.")
        return
    uid = msg.from_user.id
    mention = msg.entities and next(
        (e for e in msg.entities if e.type in ("mention", "text_mention")), None
    )
    target_id   = None
    target_name = None
    if mention:
        if mention.type == "text_mention":
            target_id   = mention.user.id
            target_name = mention.user.full_name
        elif mention.type == "mention":
            uname = msg.text[mention.offset+1:mention.offset+mention.length]
            row   = await one("SELECT user_id, full_name FROM users WHERE username=?", (uname,))
            if row:
                target_id   = row["user_id"]
                target_name = row["full_name"] or uname
    if not target_id:
        try:
            target_id = int(msg.text.strip())
        except ValueError:
            await msg.answer("❌ Geçersiz. Kullanıcıyı etiketleyin veya ID girin:")
            return
    if target_id == uid:
        await msg.answer("❌ Kendinize gönderemezsiniz!")
        return
    await state.update_data(target_id=target_id, target_name=target_name or str(target_id))
    await state.set_state(SendFSM.coin)
    bals = await all_balances(uid)
    if not bals:
        await state.clear()
        await msg.answer("💸 Bakiyeniz yok. Önce /yukle ile yükleyin.")
        return
    btns = [(f"{COINS.get(c,c)} ({v:.4f})", f"snd_coin:{c}") for c, v in bals.items()]
    rows = [btns[i:i+2] for i in range(0, len(btns), 2)]
    await msg.answer(
        f"➡️ Alıcı: <b>{target_name or target_id}</b>\n\nHangi coini göndermek istiyorsunuz?",
        reply_markup=ikb(*rows)
    )

@user_r.callback_query(F.data.startswith("snd_coin:"), StateFilter(SendFSM.coin))
async def snd_coin(call: CallbackQuery, state: FSMContext) -> None:
    coin = call.data.split(":")[1]
    uid  = call.from_user.id
    bal  = await get_balance(uid, coin)
    await state.update_data(coin=coin, bal=bal)
    await state.set_state(SendFSM.amount)
    await call.message.edit_text(
        f"➡️ Coin: <b>{COINS.get(coin, coin)}</b>\n"
        f"Bakiye: <b>{bal:.6f}</b>\n\n"
        f"Göndermek istediğiniz miktarı yazın:"
    )
    await call.answer()

@user_r.message(StateFilter(SendFSM.amount))
async def snd_amount(msg: Message, state: FSMContext) -> None:
    if msg.text.strip().lower() == "iptal":
        await state.clear()
        await msg.answer("❌ İptal edildi.")
        return
    data = await state.get_data()
    try:
        amount = float(msg.text.replace(",",".").strip())
        if amount <= 0 or amount > data["bal"]:
            raise ValueError
    except ValueError:
        await msg.answer(f"❌ Geçersiz miktar. Maks: {data['bal']:.6f}")
        return
    await state.update_data(amount=amount)
    await state.set_state(SendFSM.confirm)
    await msg.answer(
        f"➡️ <b>Gönderim Onayı</b>\n\n"
        f"Alıcı: <b>{data['target_name']}</b>\n"
        f"Coin: <b>{COINS.get(data['coin'], data['coin'])}</b>\n"
        f"Miktar: <b>{amount:.6f}</b>\n\n"
        f"Onaylıyor musunuz?",
        reply_markup=ikb(
            [("✅ Gönder", "snd_ok:yes")],
            [("❌ İptal",   "snd_ok:no")]
        )
    )

@user_r.callback_query(F.data.startswith("snd_ok:"), StateFilter(SendFSM.confirm))
async def snd_ok(call: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    if call.data == "snd_ok:no":
        await state.clear()
        await call.message.edit_text("❌ İptal.")
        await call.answer()
        return
    data = await state.get_data()
    await state.clear()
    uid = call.from_user.id
    await _do_send(call.message, uid, data["target_id"], data["target_name"], data["coin"], data["amount"], bot)
    await call.answer()

async def _do_send(msg: Message, from_uid: int, to_uid: int, to_name: str,
                   coin: str, amount: float, bot: Bot = None) -> None:
    """Bot içi kripto transfer — blockchain'e gitmez, sadece bakiye güncellenir."""
    ok = await sub_balance(from_uid, coin, amount)
    if not ok:
        await msg.answer(f"❌ Yetersiz bakiye. Mevcut: {await get_balance(from_uid, coin):.6f} {coin}")
        return
    await add_balance(to_uid, coin, amount)
    await log_wallet_tx(from_uid, "send",    coin, amount, counterpart=to_uid)
    await log_wallet_tx(to_uid,   "receive", coin, amount, counterpart=from_uid)

    sender_name = (await one("SELECT full_name FROM users WHERE user_id=?", (from_uid,)) or {}).get("full_name", str(from_uid))

    await msg.answer(
        f"✅ <b>Gönderim Başarılı!</b>\n\n"
        f"➡️ {amount:.6f} <b>{COINS.get(coin,coin)}</b>\n"
        f"Alıcı: <b>{to_name}</b>"
    )
    if bot:
        try:
            await bot.send_message(
                to_uid,
                f"⬅️ <b>Kripto Aldınız!</b>\n\n"
                f"{amount:.6f} <b>{COINS.get(coin,coin)}</b>\n"
                f"Gönderen: <b>{sender_name}</b>\n\n"
                f"/bakiye ile görüntüleyebilirsiniz."
            )
        except Exception:
            pass

# ═══════════════════════════════════════════════════════════
#  /ticaret veya /tic — Escrow anlaşması
# ═══════════════════════════════════════════════════════════

@user_r.message(Command("ticaret", "tic"))
async def cmd_ticaret(msg: Message, state: FSMContext) -> None:
    await ensure_user(msg.from_user)
    uid = msg.from_user.id
    u   = await one("SELECT is_banned FROM users WHERE user_id=?", (uid,))
    if u and u["is_banned"]:
        await msg.answer("🚫 Hesabınız yasaklandı.")
        return
    await state.clear()
    await state.set_state(DealFSM.partner)

    group_hint = ""
    if is_group(msg):
        group_hint = "\n\n💡 <i>Grup içinden başlattınız. Karşı tarafı etiketleyebilirsiniz.</i>"

    await msg.answer(
        f"📋 <b>Yeni Escrow Anlaşması — Adım 1/6</b>{group_hint}\n\n"
        f"Karşı tarafın <b>Telegram ID</b>'sini veya <b>@kullanıcıadı</b>'nı girin:\n"
        f"<i>💡 ID öğrenmek için @userinfobot</i>\n"
        f"<i>İptal için: iptal</i>"
    )

@user_r.message(StateFilter(DealFSM.partner))
async def deal_partner(msg: Message, state: FSMContext) -> None:
    if msg.text.strip().lower() == "iptal":
        await state.clear()
        await msg.answer("❌ İptal edildi.")
        return
    text       = msg.text.strip()
    partner_id = None
    mention    = msg.entities and next(
        (e for e in msg.entities if e.type in ("mention","text_mention")), None
    )
    if mention:
        if mention.type == "text_mention":
            partner_id = mention.user.id
        elif mention.type == "mention":
            uname = msg.text[mention.offset+1:mention.offset+mention.length]
            row   = await one("SELECT user_id FROM users WHERE username=?", (uname,))
            if row: partner_id = row["user_id"]
            else:
                await msg.answer("❌ Bu kullanıcı bulunamadı. Önce bota /start yazmaları gerek.")
                return
    elif text.startswith("@"):
        row = await one("SELECT user_id FROM users WHERE username=?", (text[1:],))
        if row: partner_id = row["user_id"]
        else:
            await msg.answer("❌ Kullanıcı bulunamadı.")
            return
    else:
        try: partner_id = int(text)
        except ValueError:
            await msg.answer("❌ Geçersiz. ID veya @kullanıcıadı girin.")
            return

    if partner_id == msg.from_user.id:
        await msg.answer("❌ Kendinizle anlaşma yapamazsınız!")
        return

    await state.update_data(partner_id=partner_id)
    await state.set_state(DealFSM.role)
    await msg.answer(
        f"✅ Karşı taraf: <code>{partner_id}</code>\n\n"
        f"👤 <b>Adım 2/6 — Rolünüz?</b>",
        reply_markup=ikb(
            [("🛒 Alıcıyım — Ödemeyi Ben Yapacağım",  "role:buyer")],
            [("🏪 Satıcıyım — Ödemeyi Ben Alacağım",  "role:seller")]
        )
    )

@user_r.callback_query(F.data.startswith("role:"), StateFilter(DealFSM.role))
async def deal_role(call: CallbackQuery, state: FSMContext) -> None:
    await state.update_data(role=call.data.split(":")[1])
    await state.set_state(DealFSM.amount)
    await call.message.answer(
        "💰 <b>Adım 3/6 — Tutar girin:</b>\n"
        "<i>Örnek: 500 veya 1250.50 | İptal: iptal</i>"
    )
    await call.answer()

@user_r.message(StateFilter(DealFSM.amount))
async def deal_amount(msg: Message, state: FSMContext) -> None:
    if msg.text.strip().lower() == "iptal":
        await state.clear()
        await msg.answer("❌ İptal.")
        return
    try:
        amount = float(msg.text.replace(",",".").strip())
        if amount <= 0: raise ValueError
    except ValueError:
        await msg.answer("❌ Geçersiz tutar.")
        return
    await state.update_data(amount=amount)
    await state.set_state(DealFSM.currency)
    await msg.answer(
        "💱 <b>Adım 4/6 — Para birimi:</b>",
        reply_markup=ikb(
            [("🇹🇷 TRY", "cur:TRY"), ("💵 USD", "cur:USD")],
            [("💶 EUR",   "cur:EUR"), ("💲 USDT","cur:USDT")]
        )
    )

@user_r.callback_query(F.data.startswith("cur:"), StateFilter(DealFSM.currency))
async def deal_currency(call: CallbackQuery, state: FSMContext) -> None:
    await state.update_data(currency=call.data.split(":")[1])
    await state.set_state(DealFSM.desc)
    await call.message.answer(
        "📝 <b>Adım 5/6 — Konu/Açıklama:</b>\n"
        "<i>Örnek: Logo tasarımı — 3 konsept | İptal: iptal</i>"
    )
    await call.answer()

@user_r.message(StateFilter(DealFSM.desc))
async def deal_desc(msg: Message, state: FSMContext) -> None:
    if msg.text.strip().lower() == "iptal":
        await state.clear()
        await msg.answer("❌ İptal.")
        return
    if len(msg.text.strip()) < 5:
        await msg.answer("❌ En az 5 karakter.")
        return
    await state.update_data(description=msg.text.strip())
    await state.set_state(DealFSM.method)
    await msg.answer(
        "💳 <b>Adım 6/6 — Ödeme yöntemi:</b>",
        reply_markup=ikb(
            [("🏦 IBAN / Havale",    "mth:IBAN")],
            [("💎 USDT TRC20",       "mth:USDT_TRC20"), ("⚡ TRX", "mth:TRX")],
            [("🔷 ETH",              "mth:ETH"),         ("₿ BTC",  "mth:BTC")]
        )
    )

@user_r.callback_query(F.data.startswith("mth:"), StateFilter(DealFSM.method))
async def deal_method(call: CallbackQuery, state: FSMContext) -> None:
    method = call.data.split(":")[1]
    await state.update_data(method=method)
    await state.set_state(DealFSM.confirm)
    data   = await state.get_data()
    fee    = round(data["amount"] * FEE_PERCENT / 100, 4)
    mlabel = "IBAN Havale" if method == "IBAN" else COINS.get(method, method)
    await call.message.answer(
        f"📋 <b>Anlaşma Özeti — Onay</b>\n\n"
        f"👤 Karşı taraf: <code>{data['partner_id']}</code>\n"
        f"👔 Rolünüz: <b>{'Alıcı' if data['role']=='buyer' else 'Satıcı'}</b>\n"
        f"💰 Tutar: <b>{data['amount']} {data['currency']}</b>\n"
        f"💸 Komisyon (%{FEE_PERCENT}): <b>{fee} {data['currency']}</b>\n"
        f"💵 Net satıcıya: <b>{round(data['amount']-fee,4)} {data['currency']}</b>\n"
        f"📦 Konu: {data['description']}\n"
        f"💳 Ödeme: <b>{mlabel}</b>\n\n"
        f"Onaylıyor musunuz?",
        reply_markup=ikb(
            [("✅ Onayla", "dcreate:yes")],
            [("❌ İptal",  "dcreate:no")]
        )
    )
    await call.answer()

@user_r.callback_query(F.data.startswith("dcreate:"), StateFilter(DealFSM.confirm))
async def deal_confirm(call: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    if call.data == "dcreate:no":
        await state.clear()
        await call.message.answer("❌ İptal edildi.")
        await call.answer()
        return

    data      = await state.get_data()
    await state.clear()
    code      = gen_code()
    deadline  = (datetime.now() + timedelta(hours=PAYMENT_HOURS)).isoformat()
    uid       = call.from_user.id
    buyer_id  = uid if data["role"] == "buyer"  else data["partner_id"]
    seller_id = uid if data["role"] == "seller" else data["partner_id"]
    method    = data["method"]

    deal_id = await exe(
        "INSERT INTO deals(code,buyer_id,seller_id,creator_id,amount,currency,description,method,status,deadline) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (code, buyer_id, seller_id, uid, data["amount"], data["currency"], data["description"], method, "payment_pending", deadline)
    )

    if method == "IBAN":
        ii = await cfg_get("iban_info", {})
        await exe("INSERT INTO iban_pay(deal_id,iban,bank,holder,amount,currency) VALUES(?,?,?,?,?,?)",
                  (deal_id, ii.get("iban","—"), ii.get("bank","—"), ii.get("holder","—"), data["amount"], data["currency"]))
    else:
        addr, privkey = make_addr(method)
        await exe("INSERT INTO crypto_addr(deal_id,coin,address,privkey,expected) VALUES(?,?,?,?,?)",
                  (deal_id, method, addr, privkey, data["amount"]))

    # Karşı tarafa bildirim
    partner_role = "Satıcı" if data["role"] == "buyer" else "Alıcı"
    partner_msg  = (
        f"📋 <b>Yeni Escrow Anlaşması!</b>\n\n"
        f"Kod: <b>#{code}</b> | Rolünüz: <b>{partner_role}</b>\n"
        f"Tutar: <b>{data['amount']} {data['currency']}</b>\n"
        f"Konu: {data['description']}"
    )

    # Eğer karşı taraf alıcıysa ve IBAN ise bilgileri de gönder
    if method == "IBAN" and data["partner_id"] == buyer_id:
        ii = await cfg_get("iban_info", {})
        partner_msg += (
            f"\n\n🏦 Banka: <b>{ii.get('bank','—')}</b>\n"
            f"👤 Hesap Sahibi: <b>{ii.get('holder','—')}</b>\n"
            f"💳 IBAN: <code>{ii.get('iban','—')}</code>\n"
            f"📝 Açıklama: <b>ESCROW-{code}</b>"
        )
        partner_kb = ikb([("✅ Ödemeyi Yaptım", f"buyer_paid:{deal_id}")])
    else:
        partner_kb = ikb([("📋 Anlaşmayı Gör", f"detail:{deal_id}")])

    try:
        await bot.send_message(data["partner_id"], partner_msg, reply_markup=partner_kb)
    except Exception:
        pass

    # Oluşturan kişiye göster
    if method == "IBAN" and uid == buyer_id:
        ii  = await cfg_get("iban_info", {})
        txt = (
            f"✅ <b>Anlaşma #{code} Oluşturuldu!</b>\n\n"
            f"🏦 Banka: <b>{ii.get('bank','—')}</b>\n"
            f"👤 Hesap Sahibi: <b>{ii.get('holder','—')}</b>\n"
            f"💳 IBAN: <code>{ii.get('iban','Henüz ayarlanmadı')}</code>\n\n"
            f"💰 Gönderilecek: <b>{data['amount']} {data['currency']}</b>\n"
            f"📝 Açıklama: <b>ESCROW-{code}</b>\n\n"
            f"Havaleyi yaptıktan sonra butona basın:"
        )
        await call.message.answer(txt, reply_markup=ikb([("✅ Ödemeyi Yaptım", f"buyer_paid:{deal_id}")]))
    elif method != "IBAN":
        ca  = await one("SELECT address FROM crypto_addr WHERE deal_id=?", (deal_id,))
        txt = (
            f"✅ <b>Anlaşma #{code} Oluşturuldu!</b>\n\n"
            f"🔗 {COINS.get(method,method)} Ödeme Adresi:\n"
            f"<code>{ca['address']}</code>\n\n"
            f"💰 Gönderilecek: <b>{data['amount']} {method}</b>\n"
            f"⏰ Süre: {PAYMENT_HOURS} saat — Otomatik kontrol edilir."
        ) if uid == buyer_id else (
            f"✅ <b>Anlaşma #{code} Oluşturuldu!</b>\n\n"
            f"Alıcı kripto ödeme yapacak. Blockchain'de onaylandıktan sonra bildirim alırsınız."
        )
        await call.message.answer(txt)
    else:
        await call.message.answer(
            f"✅ <b>Anlaşma #{code} Oluşturuldu!</b>\n\n"
            f"Alıcı ödeme yapacak, onaylandıktan sonra bildirim alırsınız."
        )
    await call.answer()

# ═══════════════════════════════════════════════════════════
#  /anlasmalarim
# ═══════════════════════════════════════════════════════════

@user_r.message(Command("anlasmalarim", "deals"))
async def cmd_anlasmalar(msg: Message) -> None:
    uid   = msg.from_user.id
    deals = await many(
        "SELECT * FROM deals WHERE buyer_id=? OR seller_id=? ORDER BY created_at DESC LIMIT 10",
        (uid, uid)
    )
    if not deals:
        await msg.answer("📭 Henüz anlaşmanız yok. /ticaret ile başlayın.")
        return
    await msg.answer(f"📂 <b>Son {len(deals)} Anlaşma:</b>")
    for d in deals:
        role = "🛒 Alıcı" if d["buyer_id"] == uid else "🏪 Satıcı"
        btns = []
        if d["status"] == "payment_pending":
            btns.append([("💳 Ödeme Bilgisi", f"pay_info:{d['id']}")])
        if d["status"] == "confirmed" and d["buyer_id"] == uid:
            btns.append([("✅ Teslim Aldım", f"release:{d['id']}"), ("⚠️ Dispute", f"dispute:{d['id']}")])
        btns.append([("🔍 Detay", f"detail:{d['id']}")])
        await msg.answer(f"👤 {role}\n\n{deal_text(d)}", reply_markup=ikb(*btns))

# Detay
@user_r.callback_query(F.data.startswith("detail:"))
async def deal_detail(call: CallbackQuery) -> None:
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d: await call.answer("Bulunamadı", show_alert=True); return
    uid = call.from_user.id
    if uid not in (d["buyer_id"], d["seller_id"]) and not is_admin(uid):
        await call.answer("❌ Yetkisiz", show_alert=True); return
    extra = ""
    if d["method"] == "IBAN":
        ip = await one("SELECT * FROM iban_pay WHERE deal_id=? ORDER BY id DESC LIMIT 1", (did,))
        if ip: extra = f"\n\nIBAN: <code>{ip['iban']}</code>\nDurum: <b>{ip['status']}</b>"
    else:
        ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (did,))
        if ca: extra = f"\n\nAdres: <code>{ca['address']}</code>\nAlınan: {ca['received']:.6f}/{ca['expected']}"
    await call.message.edit_text(deal_text(d) + extra)
    await call.answer()

# Ödeme bilgisi — sadece alıcıya
@user_r.callback_query(F.data.startswith("pay_info:"))
async def pay_info(call: CallbackQuery) -> None:
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d: await call.answer("Bulunamadı", show_alert=True); return
    if call.from_user.id != d["buyer_id"]:
        await call.answer("Bu bilgi sadece alıcıya görünür.", show_alert=True); return
    if d["method"] == "IBAN":
        ii = await cfg_get("iban_info", {})
        await call.message.answer(
            f"🏦 <b>IBAN Ödeme Bilgileri</b>\n\n"
            f"Banka: <b>{ii.get('bank','—')}</b>\n"
            f"Hesap Sahibi: <b>{ii.get('holder','—')}</b>\n"
            f"IBAN: <code>{ii.get('iban','—')}</code>\n\n"
            f"💰 Tutar: <b>{d['amount']} {d['currency']}</b>\n"
            f"📝 Açıklama: <b>ESCROW-{d['code']}</b>",
            reply_markup=ikb([("✅ Ödemeyi Yaptım", f"buyer_paid:{did}")])
        )
    else:
        ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (did,))
        if ca:
            await call.message.answer(
                f"🔗 <b>{COINS.get(d['method'],d['method'])} Ödeme Adresi</b>\n\n"
                f"<code>{ca['address']}</code>\n\n"
                f"💰 Gönderilecek: <b>{ca['expected']} {d['method']}</b>"
            )
    await call.answer()

# Alıcı ödeme yaptım butonu
@user_r.callback_query(F.data.startswith("buyer_paid:"))
async def buyer_paid(call: CallbackQuery, bot: Bot) -> None:
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d: await call.answer("Bulunamadı", show_alert=True); return
    if call.from_user.id != d["buyer_id"]:
        await call.answer("❌ Yetkisiz", show_alert=True); return
    if d["status"] != "payment_pending":
        await call.answer("Bu anlaşma zaten işlendi.", show_alert=True); return
    for aid in ADMIN_IDS:
        try:
            await bot.send_message(aid,
                f"💳 <b>Alıcı Ödeme Bildirdi!</b>\n\n"
                f"Anlaşma: <b>#{d['code']}</b>\n"
                f"Alıcı: <code>{d['buyer_id']}</code>\n"
                f"Tutar: <b>{d['amount']} {d['currency']}</b>\n"
                f"Konu: {d['description']}",
                reply_markup=ikb(
                    [("✅ Ödeme Geldi — Onayla", f"adm_iban_ok:{did}")],
                    [("❌ Ödeme Gelmedi — Reddet", f"adm_iban_no:{did}")]
                )
            )
        except Exception: pass
    try:
        await call.message.edit_text(
            f"✅ <b>Bildiriminiz Alındı!</b>\n\n"
            f"Admin havaleyi kontrol edip onaylayacak.\n⏳ Bekleyin."
        )
    except Exception:
        await call.message.answer("✅ Admin'e bildirildi.")
    await call.answer()

# Teslim onayı
@user_r.callback_query(F.data.startswith("release:"))
async def release_ask(call: CallbackQuery) -> None:
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d or d["buyer_id"] != call.from_user.id:
        await call.answer("❌ Yetkisiz", show_alert=True); return
    if d["status"] != "confirmed":
        await call.answer("⚠️ Henüz onaylanmadı", show_alert=True); return
    await call.message.answer(
        f"⚠️ <b>Emin misiniz?</b>\n\n<b>{d['amount']} {d['currency']}</b> satıcıya aktarılacak.",
        reply_markup=ikb(
            [("✅ Evet, Teslim Aldım", f"release_ok:{did}")],
            [("❌ Vazgeç", "close")]
        )
    )
    await call.answer()

@user_r.callback_query(F.data.startswith("release_ok:"))
async def release_ok(call: CallbackQuery, bot: Bot) -> None:
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d or d["buyer_id"] != call.from_user.id:
        await call.answer("❌ Yetkisiz", show_alert=True); return
    if d["status"] != "confirmed":
        await call.answer("Zaten işlendi", show_alert=True); return
    await exe("UPDATE deals SET status='released' WHERE id=?", (did,))
    fee = round(d["amount"] * FEE_PERCENT / 100, 4)
    net = round(d["amount"] - fee, 4)
    try:
        await call.message.edit_text("✅ Onaylandı! Satıcıya bildirim gönderildi.")
    except Exception:
        pass
    await call.answer()
    asyncio.create_task(_start_seller_payout(bot, d, net))
    for aid in ADMIN_IDS:
        try:
            await bot.send_message(aid,
                f"💸 <b>#{d['code']} Onaylandı</b>\n"
                f"Satıcı: <code>{d['seller_id']}</code> | Net: {net} {d['currency']}\n"
                f"⏳ Satıcı ödeme yöntemi seçiyor...",
                reply_markup=ikb(
                    [("💸 Manuel Kripto Gönder", f"adm_payout:{did}")],
                    [("✅ IBAN Gönderildi",       f"adm_iban_done:{did}")]
                )
            )
        except Exception: pass

async def _start_seller_payout(bot: Bot, deal: Dict, net: float) -> None:
    """Satıcıya ödeme yöntemi seçtir. Kripto sadece bakiye varsa çıkar."""
    btns = [[("🏦 IBAN / EFT ile al", f"seller_pay:{deal['id']}:iban")]]
    if deal["method"] in COINS:
        ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (deal["id"],))
        if ca:
            bal = await chain_balance(ca["coin"], ca["address"])
            if bal >= net * 0.99:
                lbl = COINS.get(deal["method"], deal["method"])
                btns.append([(f"🔗 {lbl} ile al (bakiye: {bal:.4f})", f"seller_pay:{deal['id']}:crypto")])
    await bot.send_message(
        deal["seller_id"],
        f"🎉 <b>Alıcı Onayladı!</b>\n\n"
        f"Anlaşma: <b>#{deal['code']}</b>\n"
        f"💰 Net tutar: <b>{net} {deal['currency']}</b>\n\n"
        f"Ödemeyi nasıl almak istersiniz?",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=t, callback_data=cb) for t, cb in row]
            for row in btns
        ])
    )
    await cfg_set(f"payout_pending:{deal['id']}", {
        "seller_id": deal["seller_id"], "deal_id": deal["id"],
        "coin": deal["method"], "amount": net,
        "currency": deal["currency"], "code": deal["code"],
    })

@user_r.callback_query(F.data.startswith("seller_pay:"))
async def seller_pay_method(call: CallbackQuery) -> None:
    parts   = call.data.split(":")
    deal_id = int(parts[1])
    method  = parts[2]
    uid     = call.from_user.id
    pending = await cfg_get(f"payout_pending:{deal_id}")
    if not pending or pending.get("seller_id") != uid:
        await call.answer("Süresi doldu ya da yetkisiz.", show_alert=True); return
    if method == "iban":
        await cfg_set(f"iban_payout:{deal_id}", {
            "seller_id": uid, "deal_id": deal_id,
            "amount": pending["amount"], "currency": pending["currency"],
            "code": pending["code"], "step": "iban",
        })
        await cfg_del(f"payout_pending:{deal_id}")
        await call.message.edit_text(
            f"🏦 <b>IBAN Bilgilerinizi Girin</b>\n\n"
            f"Net tutar: <b>{pending['amount']} {pending['currency']}</b>\n\n"
            f"IBAN numaranızı gönderin:\n<i>Örnek: TR38 0015 7000 0000 0202 1155 21</i>"
        )
    elif method == "crypto":
        coin = pending.get("coin","")
        if coin not in COINS:
            await call.answer("Kripto seçeneği yok.", show_alert=True); return
        await cfg_set(f"crypto_payout:{deal_id}", {
            "seller_id": uid, "deal_id": deal_id,
            "coin": coin, "amount": pending["amount"], "code": pending["code"],
        })
        await cfg_del(f"payout_pending:{deal_id}")
        await call.message.edit_text(
            f"🔗 <b>{COINS.get(coin,coin)} Adresinizi Girin</b>\n\n"
            f"Net tutar: <b>{pending['amount']} {coin}</b>\n\n"
            f"Cüzdan adresinizi gönderin:"
        )
    await call.answer()

# Dispute
@user_r.callback_query(F.data.startswith("dispute:"))
async def dispute(call: CallbackQuery, bot: Bot) -> None:
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d or d["status"] in ("released","cancelled"): return
    await exe("UPDATE deals SET status='disputed' WHERE id=?", (did,))
    for aid in ADMIN_IDS:
        try:
            await bot.send_message(aid,
                f"⚠️ <b>Dispute!</b>\n#{d['code']} | {d['amount']} {d['currency']}\n"
                f"Alıcı: <code>{d['buyer_id']}</code> | Satıcı: <code>{d['seller_id']}</code>",
                reply_markup=ikb(
                    [("✅ Alıcı Haklı", f"adm_dis_buyer:{did}")],
                    [("✅ Satıcı Haklı", f"adm_dis_seller:{did}")]
                )
            )
        except Exception: pass
    await call.message.answer("⚠️ Dispute açıldı. Admin inceleyecek.")
    await call.answer()

@user_r.callback_query(F.data == "close")
async def close_cb(call: CallbackQuery) -> None:
    try: await call.message.delete()
    except: pass
    await call.answer()

# ═══════════════════════════════════════════════════════════
#  SATICI PAYOUT CATCHER (state=None iken)
# ═══════════════════════════════════════════════════════════

@user_r.message(StateFilter(None), F.text)
async def catch_seller_iban(msg: Message, bot: Bot) -> None:
    uid  = msg.from_user.id
    text = msg.text.strip()
    rows = await many("SELECT key, value FROM settings WHERE key LIKE 'iban_payout:%'")
    for row in rows:
        try: data = json.loads(row["value"])
        except: continue
        if data.get("seller_id") != uid: continue
        step = data.get("step","iban")
        if step == "iban":
            iban = text.replace(" ","").upper()
            if len(iban) < 16:
                await msg.answer("❌ Geçersiz IBAN.\n<i>Örnek: TR38 0015 7000 0000 0202 1155 21</i>"); return
            data["iban"] = iban; data["step"] = "bank"
            await cfg_set(row["key"], data)
            await msg.answer("🏦 Banka adını girin:")
            return
        elif step == "bank":
            if len(text) < 2:
                await msg.answer("❌ Geçersiz banka adı."); return
            data["bank"] = text; data["step"] = "holder"
            await cfg_set(row["key"], data)
            await msg.answer("👤 Hesap sahibinin tam adını girin:")
            return
        elif step == "holder":
            if len(text) < 3:
                await msg.answer("❌ Geçersiz isim."); return
            data["holder"] = text
            await msg.answer(
                f"✅ <b>Bilgiler Alındı!</b>\n\n"
                f"IBAN: <code>{data['iban']}</code>\n"
                f"Banka: {data['bank']}\nHesap: {data['holder']}\n\n"
                f"💰 Tutar: <b>{data['amount']} {data['currency']}</b>\n\n"
                f"⏳ Admin en kısa sürede ödeyecek."
            )
            for aid in ADMIN_IDS:
                try:
                    await bot.send_message(aid,
                        f"🏦 <b>Satıcı IBAN Bilgisi!</b>\n\n"
                        f"Anlaşma: #{data['code']}\nSatıcı: <code>{uid}</code>\n\n"
                        f"💳 IBAN: <code>{data['iban']}</code>\n"
                        f"🏛 Banka: {data['bank']}\n👤 Hesap: {data['holder']}\n\n"
                        f"💰 Gönderilecek: <b>{data['amount']} {data['currency']}</b>",
                        reply_markup=ikb([("✅ Ödemeyi Yaptım", f"adm_iban_done:{data['deal_id']}")])
                    )
                except Exception: pass
            await cfg_del(row["key"])
            return

@user_r.message(StateFilter(None), F.text)
async def catch_crypto_payout(msg: Message, bot: Bot) -> None:
    uid  = msg.from_user.id
    rows = await many("SELECT key, value FROM settings WHERE key LIKE 'crypto_payout:%'")
    for row in rows:
        try: data = json.loads(row["value"])
        except: continue
        if data.get("seller_id") != uid: continue
        addr = msg.text.strip(); coin = data["coin"]
        valid = (
            (coin in ("TRX","USDT_TRC20") and addr.startswith("T") and len(addr)==34) or
            (coin=="ETH" and addr.startswith("0x") and len(addr)==42) or
            (coin=="BTC" and (addr.startswith("1") or addr.startswith("3") or addr.startswith("bc1")))
        )
        if not valid:
            await msg.answer(f"❌ Geçersiz {coin} adresi. Tekrar deneyin:"); return
        ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (data["deal_id"],))
        if not ca:
            await msg.answer("❌ Kripto kaydı bulunamadı."); return
        await msg.answer(f"⏳ {data['amount']} {coin} gönderiliyor...")
        tx = await send_crypto(coin, ca["address"], ca["privkey"], addr, data["amount"])
        if tx:
            await msg.answer(f"🎉 <b>Gönderildi!</b>\n\n💰 {data['amount']} {coin}\n📬 <code>{addr}</code>\n🔗 <code>{tx}</code>")
            d = await one("SELECT * FROM deals WHERE id=?", (data["deal_id"],))
            if d:
                try:
                    await bot.send_message(d["buyer_id"],
                        f"✅ <b>Anlaşma Tamamlandı!</b>\n\nAnlaşma: #{data['code']}\nSatıcıya ödeme yapıldı.")
                except Exception: pass
        else:
            await msg.answer("⚠️ Otomatik gönderim başarısız. Admin manuel gönderecek.")
            for aid in ADMIN_IDS:
                try:
                    await bot.send_message(aid,
                        f"🚨 Kripto BAŞARISIZ!\n#{data['code']} | {data['amount']} {coin}\nHedef: {addr}",
                        reply_markup=ikb([("💸 Manuel Gönder", f"adm_payout:{data['deal_id']}")]))
                except Exception: pass
        await cfg_del(row["key"])
        return

# ═══════════════════════════════════════════════════════════
#  ADMİN PANEL
# ═══════════════════════════════════════════════════════════

@admin_r.message(Command("admin"))
async def admin_cmd(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id):
        await msg.answer("🚫 Yetkisiz!"); return
    await state.clear()
    await msg.answer("👑 <b>Admin Paneli</b>", reply_markup=ikb(
        [("🏦 IBAN Ayarla",      "adm:iban"),        ("📋 Bekleyen IBAN", "adm:pending_iban")],
        [("💎 Kripto Bakiyeler", "adm:balances"),     ("💸 Fon Gönder",    "adm:send")],
        [("📊 Anlaşmalar",      "adm:deals"),        ("⚠️ Disputelar",   "adm:disputes")],
        [("👥 Kullanıcılar",    "adm:users"),        ("📢 Duyuru",        "adm:broadcast")],
        [("📈 İstatistikler",   "adm:stats"),        ("👛 Cüzdan Özeti",  "adm:wallets")]
    ))

@admin_r.callback_query(F.data.startswith("adm:"))
async def admin_cb(call: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    action = call.data.split(":")[1]

    if action == "iban":
        ii  = await cfg_get("iban_info", {})
        cur = f"\n\nMevcut: <code>{ii.get('iban','—')}</code> | {ii.get('bank','—')}" if ii else ""
        await state.set_state(AdminFSM.iban_val)
        await call.message.answer(f"🏦 <b>IBAN Ayarla</b>{cur}\n\nYeni IBAN girin (TR... 26 karakter):")

    elif action == "pending_iban":
        pays = await many("SELECT ip.*, d.code, d.buyer_id, d.description FROM iban_pay ip JOIN deals d ON ip.deal_id=d.id WHERE ip.status='waiting' ORDER BY ip.created_at DESC")
        if not pays: await call.message.answer("✅ Bekleyen IBAN yok.")
        for p in pays:
            await call.message.answer(
                f"🏦 <b>IBAN Ödemesi</b>\n\nAnlaşma: #{p['code']}\nAlıcı: <code>{p['buyer_id']}</code>\nTutar: {p['amount']} {p['currency']}",
                reply_markup=ikb([("✅ Onayla", f"adm_iban_ok:{p['deal_id']}"), ("❌ Reddet", f"adm_iban_no:{p['deal_id']}")])
            )

    elif action == "balances":
        await call.message.answer("⏳ Sorgulanıyor...")
        addrs = await many("SELECT ca.*, d.code FROM crypto_addr ca JOIN deals d ON ca.deal_id=d.id WHERE d.status NOT IN ('cancelled','released') LIMIT 20")
        if not addrs: await call.message.answer("💤 Aktif kripto adresi yok.")
        else:
            txt = "💎 <b>Kripto Bakiyeleri</b>\n\n"
            btns = []
            for a in addrs:
                bal  = await chain_balance(a["coin"], a["address"])
                txt += f"#{a['code']} {a['coin']}: {bal:.6f} / {a['expected']}\n"
                if bal > 0: btns.append([(f"💸 #{a['code']} Gönder", f"adm_bal_send:{a['id']}")])
            await call.message.answer(txt, reply_markup=ikb(*btns) if btns else None)

    elif action == "wallets":
        # Tüm kullanıcı bakiyelerinin özeti
        rows = await many("SELECT coin, SUM(amount) total FROM balances GROUP BY coin")
        if not rows: await call.message.answer("Kullanıcı bakiyesi yok.")
        else:
            txt = "👛 <b>Toplam Kullanıcı Bakiyeleri</b>\n\n"
            for r in rows:
                txt += f"{COINS.get(r['coin'],r['coin'])}: <b>{r['total']:.6f}</b>\n"
            await call.message.answer(txt)

    elif action == "deals":
        await call.message.answer("📊 <b>Filtre:</b>", reply_markup=ikb(
            [("⏳ Bekleyen", "adm_dl:payment_pending"), ("🔐 Onaylı", "adm_dl:confirmed")],
            [("💸 Tamamlandı","adm_dl:released"),       ("❌ İptal",  "adm_dl:cancelled")],
            [("⚠️ Dispute",  "adm_dl:disputed"),         ("📋 Tümü",  "adm_dl:all")]
        ))

    elif action == "disputes":
        deals = await many("SELECT * FROM deals WHERE status='disputed' ORDER BY created_at DESC")
        if not deals: await call.message.answer("✅ Dispute yok.")
        for d in deals:
            await call.message.answer(deal_text(d), reply_markup=ikb(
                [("✅ Alıcı Haklı", f"adm_dis_buyer:{d['id']}")],
                [("✅ Satıcı Haklı", f"adm_dis_seller:{d['id']}")]
            ))

    elif action == "stats":
        total    = await one("SELECT COUNT(*) c FROM deals")
        released = await one("SELECT COUNT(*) c FROM deals WHERE status='released'")
        pending  = await one("SELECT COUNT(*) c FROM deals WHERE status='payment_pending'")
        disputed = await one("SELECT COUNT(*) c FROM deals WHERE status='disputed'")
        vol      = await one("SELECT COALESCE(SUM(amount),0) s FROM deals WHERE status='released'")
        users    = await one("SELECT COUNT(*) c FROM users")
        tx_count = await one("SELECT COUNT(*) c FROM wallet_tx")
        await call.message.answer(
            f"📈 <b>İstatistikler</b>\n\n"
            f"👥 Kullanıcı: {users['c']}\n"
            f"📋 Toplam Anlaşma: {total['c']}\n"
            f"⏳ Bekleyen: {pending['c']} | ✅ Tamamlanan: {released['c']}\n"
            f"⚠️ Dispute: {disputed['c']}\n"
            f"💰 Hacim: {vol['s']:.2f}\n"
            f"💸 Cüzdan İşlemi: {tx_count['c']}"
        )

    elif action == "broadcast":
        await state.set_state(AdminFSM.broadcast)
        await call.message.answer("📢 Mesajı yazın:")

    elif action == "users":
        users = await many("SELECT * FROM users ORDER BY created_at DESC LIMIT 20")
        txt   = "👥 <b>Son 20 Kullanıcı</b>\n\n"
        btns  = []
        for u in users:
            st = "🚫" if u["is_banned"] else "✅"
            txt += f"{st} {u['full_name'] or 'İsimsiz'} | <code>{u['user_id']}</code>\n"
            if u["is_banned"]:
                btns.append([(f"🔓 {u['user_id']}", f"adm_unban:{u['user_id']}")])
            else:
                btns.append([(f"🚫 {u['user_id']}", f"adm_ban:{u['user_id']}")])
        await call.message.answer(txt, reply_markup=ikb(*btns) if btns else None)

    elif action == "send":
        addrs = await many("SELECT ca.*, d.code FROM crypto_addr ca JOIN deals d ON ca.deal_id=d.id WHERE ca.received>0 OR ca.status='received'")
        if not addrs: await call.message.answer("💤 Bakiyeli adres yok.")
        else:
            btns = [[(f"#{a['code']} {a['coin']}", f"adm_bal_send:{a['id']}")] for a in addrs]
            await call.message.answer("💸 Hangi adresten?", reply_markup=ikb(*btns))

    await call.answer()

# ─── Admin IBAN FSM ───────────────────────────────────────

@admin_r.message(StateFilter(AdminFSM.iban_val))
async def adm_iban_val(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id): return
    iban = msg.text.strip().replace(" ","").upper()
    if not (iban.startswith("TR") and len(iban)==26):
        await msg.answer("❌ Geçersiz IBAN!"); return
    await state.update_data(iban=iban); await state.set_state(AdminFSM.iban_bank)
    await msg.answer("🏦 Banka adı:")

@admin_r.message(StateFilter(AdminFSM.iban_bank))
async def adm_iban_bank(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id): return
    await state.update_data(bank=msg.text.strip()); await state.set_state(AdminFSM.iban_holder)
    await msg.answer("👤 Hesap sahibi:")

@admin_r.message(StateFilter(AdminFSM.iban_holder))
async def adm_iban_holder(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id): return
    data = await state.get_data(); await state.clear()
    ii   = {"iban": data["iban"], "bank": data["bank"], "holder": msg.text.strip()}
    await cfg_set("iban_info", ii)
    await msg.answer(f"✅ IBAN Kaydedildi!\n\nIBAN: <code>{ii['iban']}</code>\nBanka: {ii['bank']}\nSahip: {ii['holder']}")

# ─── Admin IBAN Onayla / Reddet ───────────────────────────

@admin_r.callback_query(F.data.startswith("adm_iban_ok:"))
async def adm_iban_ok(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    await exe("UPDATE iban_pay SET status='confirmed', admin_id=?, confirmed_at=? WHERE deal_id=?",
              (call.from_user.id, datetime.now().isoformat(), did))
    await exe("UPDATE deals SET status='confirmed' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    try:
        await bot.send_message(d["buyer_id"],
            f"✅ <b>Ödemeniz Onaylandı!</b>\n\nAnlaşma: #{d['code']}\n"
            f"📦 Ürünü alınca teslim onayı verin:",
            reply_markup=ikb(
                [("✅ Teslim Aldım", f"release:{did}")],
                [("⚠️ Dispute Aç",   f"dispute:{did}")]
            )
        )
    except Exception: pass
    try:
        await bot.send_message(d["seller_id"],
            f"🔔 <b>Alıcı Ödemesi Onaylandı!</b>\n\nAnlaşma: #{d['code']}\n"
            f"⏳ Ürünü teslim edin — alıcı onayladıktan sonra ödemeniz yapılacak.")
    except Exception: pass
    try: await call.message.edit_text("✅ Onaylandı.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_iban_no:"))
async def adm_iban_no(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    await exe("UPDATE iban_pay SET status='rejected' WHERE deal_id=?", (did,))
    await exe("UPDATE deals SET status='cancelled' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    for uid in [d["buyer_id"], d["seller_id"]]:
        try: await bot.send_message(uid, f"❌ Anlaşma #{d['code']} iptal edildi.")
        except: pass
    try: await call.message.edit_text("❌ Reddedildi.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_iban_done:"))
async def adm_iban_done(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if d:
        fee = round(d["amount"] * FEE_PERCENT / 100, 4)
        net = round(d["amount"] - fee, 4)
        try:
            await bot.send_message(d["seller_id"],
                f"🎉 <b>Ödemeniz Yapıldı!</b>\n\nAnlaşma: #{d['code']}\n"
                f"💰 Net: <b>{net} {d['currency']}</b>\n✅ Hesabınıza aktarıldı!")
        except Exception: pass
        try:
            await bot.send_message(d["buyer_id"],
                f"✅ <b>Anlaşma Tamamlandı!</b>\n\nAnlaşma: #{d['code']}")
        except Exception: pass
    try: await call.message.edit_text("✅ IBAN havalesi yapıldı. Taraflara bildirim gönderildi.")
    except: pass
    await call.answer()

# ─── Anlaşma Listesi ──────────────────────────────────────

@admin_r.callback_query(F.data.startswith("adm_dl:"))
async def adm_deal_list(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    status = call.data.split(":")[1]
    q      = "SELECT * FROM deals ORDER BY created_at DESC LIMIT 15" if status == "all" \
             else "SELECT * FROM deals WHERE status=? ORDER BY created_at DESC LIMIT 15"
    deals  = await many(q) if status == "all" else await many(q, (status,))
    if not deals: await call.message.answer("📭 Yok.")
    for d in deals:
        await call.message.answer(deal_text(d), reply_markup=ikb([("🔧 Yönet", f"adm_mgmt:{d['id']}")]))
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_mgmt:"))
async def adm_mgmt(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d: await call.answer("Yok",show_alert=True); return
    btns = []
    if d["status"] not in ("released","cancelled"): btns.append([("❌ İptal Et", f"adm_cancel:{did}")])
    if d["status"] in ("confirmed","payment_pending"): btns.append([("💸 Zorla Serbest Bırak", f"adm_force_release:{did}")])
    await call.message.answer(deal_text(d), reply_markup=ikb(*btns) if btns else None)
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_cancel:"))
async def adm_cancel(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    await exe("UPDATE deals SET status='cancelled' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    for uid in [d["buyer_id"],d["seller_id"]]:
        try: await bot.send_message(uid, f"❌ Anlaşma #{d['code']} admin tarafından iptal edildi.")
        except: pass
    try: await call.message.edit_text("❌ İptal edildi.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_force_release:"))
async def adm_force_release(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    await exe("UPDATE deals SET status='released' WHERE id=?", (did,))
    fee = round(d["amount"]*FEE_PERCENT/100, 4)
    net = round(d["amount"]-fee, 4)
    asyncio.create_task(_start_seller_payout(bot, d, net))
    try: await call.message.edit_text("✅ Serbest bırakıldı. Payout başlatıldı.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_dis_buyer:"))
async def adm_dis_buyer(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    await exe("UPDATE deals SET status='cancelled' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    try: await bot.send_message(d["buyer_id"], f"✅ Dispute: Haklı bulundunuz. #{d['code']} iptal.")
    except: pass
    try: await bot.send_message(d["seller_id"], f"⚠️ Dispute: Alıcı haklı. #{d['code']} iptal.")
    except: pass
    try: await call.message.edit_text("✅ Alıcı lehine.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_dis_seller:"))
async def adm_dis_seller(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    await exe("UPDATE deals SET status='released' WHERE id=?", (did,))
    fee = round(d["amount"]*FEE_PERCENT/100,4); net = round(d["amount"]-fee,4)
    asyncio.create_task(_start_seller_payout(bot, d, net))
    try: await bot.send_message(d["seller_id"], f"✅ Dispute: Haklı bulundunuz. Payout başlatıldı.")
    except: pass
    try: await bot.send_message(d["buyer_id"], f"⚠️ Dispute: Satıcı haklı. #{d['code']}")
    except: pass
    try: await call.message.edit_text("✅ Satıcı lehine.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_bal_send:"))
async def adm_bal_send(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    aid = int(call.data.split(":")[1])
    ca  = await one("SELECT * FROM crypto_addr WHERE id=?", (aid,))
    if not ca: await call.answer("Yok",show_alert=True); return
    await state.update_data(ca_id=aid, ca_coin=ca["coin"], ca_addr=ca["address"], ca_priv=ca["privkey"])
    await state.set_state(AdminFSM.send_to)
    await call.message.answer(f"💸 Gönder — {ca['coin']}\nHedef adresi:")
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_payout:"))
async def adm_payout(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    ca  = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (did,))
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not ca or not d: await call.answer("Yok",show_alert=True); return
    net = round(d["amount"] - d["amount"]*FEE_PERCENT/100, 6)
    await state.update_data(ca_id=ca["id"], ca_coin=ca["coin"], ca_addr=ca["address"],
                            ca_priv=ca["privkey"], forced_amount=net, deal_id=did)
    await state.set_state(AdminFSM.send_to)
    await call.message.answer(f"💸 Satıcıya gönder — Net: {net} {ca['coin']}\nSatıcı adresini girin:")
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_manual_wd:"))
async def adm_manual_wd(call: CallbackQuery, bot: Bot) -> None:
    """Manuel çekim — admin onaylar ve gerçekten gönderir."""
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    parts  = call.data.split(":")  # adm_manual_wd:uid:coin:amount:addr
    uid    = int(parts[1])
    coin   = parts[2]
    amount = float(parts[3])
    addr   = parts[4]
    await call.message.answer(f"⏳ Manuel çekim: {amount} {coin} → {addr}")
    tx = await master_send(coin, addr, amount)
    if tx:
        await log_wallet_tx(uid, "withdraw", coin, amount, tx_hash=tx, note=f"Admin manuel → {addr}")
        await call.message.answer(f"✅ Gönderildi! TX: <code>{tx}</code>")
        try: await bot.send_message(uid, f"✅ Çekim tamamlandı!\n{amount} {coin} → <code>{addr}</code>\nTX: <code>{tx}</code>")
        except: pass
    else:
        await call.message.answer("❌ Gönderim başarısız. Manuel işlem gerekiyor.")
    await call.answer()

@admin_r.message(StateFilter(AdminFSM.send_to))
async def adm_send_to(msg: Message, state: FSMContext, bot: Bot) -> None:
    if not is_admin(msg.from_user.id): return
    await state.update_data(send_to=msg.text.strip())
    data = await state.get_data()
    if "forced_amount" in data:
        await _adm_do_send(msg, state, bot)
    else:
        await state.set_state(AdminFSM.send_amt)
        await msg.answer("💰 Miktar:")

@admin_r.message(StateFilter(AdminFSM.send_amt))
async def adm_send_amt(msg: Message, state: FSMContext, bot: Bot) -> None:
    if not is_admin(msg.from_user.id): return
    try: amount = float(msg.text.replace(",","."))
    except: await msg.answer("❌ Geçersiz miktar."); return
    await state.update_data(send_amount=amount)
    await _adm_do_send(msg, state, bot)

async def _adm_do_send(msg: Message, state: FSMContext, bot: Bot) -> None:
    data   = await state.get_data()
    amount = data.get("send_amount") or data.get("forced_amount")
    if not amount: return
    await state.clear()
    await msg.answer(f"⏳ {amount} {data['ca_coin']} gönderiliyor...")
    tx = await send_crypto(data["ca_coin"], data["ca_addr"], data["ca_priv"], data["send_to"], amount)
    if tx:
        await msg.answer(f"✅ <b>Başarılı!</b>\nTX: <code>{tx}</code>\n{amount} {data['ca_coin']} → <code>{data['send_to']}</code>")
        await exe("INSERT INTO txlog(type,amount,currency,from_address,to_address,tx_hash,note) VALUES(?,?,?,?,?,?,?)",
                  ("admin_send", amount, data["ca_coin"], data["ca_addr"], data["send_to"], tx, "Admin"))
        # Satıcıya bildir
        deal_id = data.get("deal_id")
        if deal_id:
            d = await one("SELECT * FROM deals WHERE id=?", (deal_id,))
            if d:
                try: await bot.send_message(d["seller_id"],
                    f"🎉 <b>Ödemeniz Gönderildi!</b>\n\nAnlaşma: #{d['code']}\n"
                    f"💰 {amount} {data['ca_coin']}\nTX: <code>{tx}</code>")
                except: pass
                try: await bot.send_message(d["buyer_id"], f"✅ Anlaşma tamamlandı! #{d['code']}")
                except: pass
    else:
        await msg.answer("❌ Gönderim başarısız!")

@admin_r.message(StateFilter(AdminFSM.broadcast))
async def adm_broadcast(msg: Message, state: FSMContext, bot: Bot) -> None:
    if not is_admin(msg.from_user.id): return
    await state.clear()
    users = await many("SELECT user_id FROM users WHERE is_banned=0")
    ok = fail = 0
    for u in users:
        try: await bot.send_message(u["user_id"], f"📢 <b>Duyuru:</b>\n\n{msg.text}"); ok+=1
        except: fail+=1
        await asyncio.sleep(0.05)
    await msg.answer(f"📢 Tamamlandı! ✅{ok} ❌{fail}")

@admin_r.callback_query(F.data.startswith("adm_ban:"))
async def adm_ban(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    uid = int(call.data.split(":")[1])
    await exe("UPDATE users SET is_banned=1 WHERE user_id=?", (uid,))
    try: await bot.send_message(uid, "🚫 Hesabınız yasaklandı.")
    except: pass
    await call.answer(f"🚫 {uid} yasaklandı", show_alert=True)

@admin_r.callback_query(F.data.startswith("adm_unban:"))
async def adm_unban(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    uid = int(call.data.split(":")[1])
    await exe("UPDATE users SET is_banned=0 WHERE user_id=?", (uid,))
    try: await bot.send_message(uid, "✅ Yasağınız kaldırıldı.")
    except: pass
    await call.answer(f"✅ {uid} yasak kaldırıldı", show_alert=True)

# ═══════════════════════════════════════════════════════════
#  MONİTÖRLER (arka plan)
# ═══════════════════════════════════════════════════════════

async def escrow_monitor(bot: Bot) -> None:
    """Escrow kripto ödemelerini izle."""
    log.info("🔍 Escrow monitörü başlatıldı")
    while True:
        try:
            addrs = await many("""
                SELECT ca.*, d.id AS did, d.code, d.buyer_id, d.seller_id, d.method
                FROM crypto_addr ca JOIN deals d ON ca.deal_id=d.id
                WHERE ca.status='waiting' AND d.status='payment_pending'
            """)
            for a in addrs:
                try:
                    bal = await chain_balance(a["coin"], a["address"])
                    if bal >= float(a["expected"]) * 0.99:
                        await exe("UPDATE crypto_addr SET status='received', received=? WHERE id=?", (bal, a["id"]))
                        await exe("UPDATE deals SET status='confirmed' WHERE id=?", (a["did"],))
                        log.info("✅ Escrow ödeme: #%s %s %s", a["code"], bal, a["coin"])
                        try:
                            await bot.send_message(a["buyer_id"],
                                f"✅ <b>Ödemeniz Alındı!</b>\n\nAnlaşma: #{a['code']}\n"
                                f"💰 {bal:.6f} {a['coin']}\n\n📦 Ürünü alınca onaylayın:",
                                reply_markup=ikb(
                                    [("✅ Teslim Aldım", f"release:{a['did']}")],
                                    [("⚠️ Dispute Aç",   f"dispute:{a['did']}")]
                                )
                            )
                        except Exception: pass
                        try:
                            await bot.send_message(a["seller_id"],
                                f"🔔 <b>Ödeme Onaylandı!</b>\n\nAnlaşma: #{a['code']}\n"
                                f"⏳ Alıcı onayladıktan sonra ödemeniz yapılacak.")
                        except Exception: pass
                    elif bal > 0:
                        await exe("UPDATE crypto_addr SET received=? WHERE id=?", (bal, a["id"]))
                except Exception as e:
                    log.warning("Escrow monitor hata: %s", e)
        except Exception as e:
            log.error("Escrow monitor kritik: %s", e)
        await asyncio.sleep(MONITOR_SEC)


async def deposit_monitor(bot: Bot) -> None:
    """Kullanıcı bakiye yükleme adreslerini izle."""
    log.info("💰 Deposit monitörü başlatıldı")
    while True:
        try:
            addrs = await many(
                "SELECT * FROM deposit_addr WHERE status='waiting' ORDER BY created_at DESC"
            )
            for a in addrs:
                try:
                    bal = await chain_balance(a["coin"], a["address"])
                    if bal > float(a["received"]) + 0.000001:
                        new_amount = bal - float(a["received"])
                        await exe("UPDATE deposit_addr SET received=? WHERE id=?", (bal, a["id"]))

                        # Bakiyeye ekle
                        total = await add_balance(a["user_id"], a["coin"], new_amount)
                        await log_wallet_tx(a["user_id"], "deposit", a["coin"], new_amount)

                        log.info("💰 Deposit: user=%s +%s %s", a["user_id"], new_amount, a["coin"])
                        try:
                            await bot.send_message(
                                a["user_id"],
                                f"📥 <b>Bakiye Yüklendi!</b>\n\n"
                                f"💰 +{new_amount:.6f} {COINS.get(a['coin'],a['coin'])}\n"
                                f"📊 Toplam bakiye: <b>{total:.6f} {a['coin']}</b>\n\n"
                                f"/bakiye ile görüntüleyebilirsiniz."
                            )
                        except Exception: pass

                        # Master cüzdana sweeping (isteğe bağlı)
                        # Adreste biriken kripto master'a sweep edilebilir
                        # Şimdilik bakiye veri tabanında tutuluyor, master gönderim çekimde yapılıyor
                except Exception as e:
                    log.warning("Deposit monitor hata: %s", e)
        except Exception as e:
            log.error("Deposit monitor kritik: %s", e)
        await asyncio.sleep(MONITOR_SEC)

# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════

async def main() -> None:
    await db_init()
    log.info("✅ DB hazır: %s", DB_PATH)

    bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
    dp  = Dispatcher(storage=MemoryStorage())
    dp["bot"] = bot

    dp.include_router(admin_r)
    dp.include_router(user_r)

    asyncio.create_task(escrow_monitor(bot))
    asyncio.create_task(deposit_monitor(bot))

    log.info("🤖 Escrow+Wallet Bot v4.0 | Admin: %s | Fee: %.1f%%", ADMIN_IDS, FEE_PERCENT)
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())


if __name__ == "__main__":
    print("╔══════════════════════════════════════════╗")
    print("║   Escrow + Wallet Bot v4.0               ║")
    print("╠══════════════════════════════════════════╣")
    print("║ ENV değişkenleri:                        ║")
    print("║  BOT_TOKEN   — Telegram bot token        ║")
    print("║  ADMIN_IDS   — 123,456 formatında        ║")
    print("║  MASTER_TRX_ADDR / MASTER_TRX_KEY        ║")
    print("║  MASTER_ETH_ADDR / MASTER_ETH_KEY        ║")
    print("║  TRON_API_KEY (opsiyonel)                ║")
    print("╚══════════════════════════════════════════╝")
    asyncio.run(main())
