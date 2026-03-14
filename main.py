#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Escrow + Wallet Bot v5.0
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
BOT_TOKEN     = os.getenv("BOT_TOKEN",      "8355587538:AAFq6bCO-KHzkMEks2Jiu3dEW3PzSBnVesA")
ADMIN_IDS     = [int(x) for x in os.getenv("ADMIN_IDS", "7672180974").split(",") if x.strip()]
DB_PATH       = os.getenv("DB_PATH",        "escrow.db")
FEE_PERCENT   = float(os.getenv("FEE_PERCENT",    "4.0"))
PAYMENT_HOURS = int(os.getenv("PAYMENT_HOURS",    "24"))
MONITOR_SEC   = int(os.getenv("MONITOR_SEC",      "30"))
TRON_API_KEY  = os.getenv("TRON_API_KEY",   "")

ADMIN_APPROVE_HOURS = int(os.getenv("ADMIN_APPROVE_HOURS", "72"))

MASTER_TRX_ADDR = os.getenv("MASTER_TRX_ADDR", "TE8o7mf1Z92ELZzUS6dY57t4SvcCBCZbyB")
MASTER_TRX_KEY  = os.getenv("MASTER_TRX_KEY",  "2a7de4ef6d80a393d7b16384b90bcdb3df0eb1ef15ba1c827e78b992245a9e36")
MASTER_ETH_ADDR = os.getenv("MASTER_ETH_ADDR", "0xdc1949e9E6dBEDEd4Ccb03E92007B302638F6278")
MASTER_ETH_KEY  = os.getenv("MASTER_ETH_KEY",  "60a86f6f474b3f0743d4bfaa4591e9e55e8cb14f57a2d78ab42a93c8660dea39")
MASTER_BTC_ADDR = os.getenv("MASTER_BTC_ADDR", "")
# ═══════════════════════════════════════════════════════════

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
log = logging.getLogger("escrow")

USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

COINS: Dict[str, str] = {
    "USDT_TRC20": "USDT (TRC20)",
    "USDT":       "USDT (TRC20)",
    "TRX":        "TRX",
    "ETH":        "ETH",
    "BTC":        "BTC",
}

COIN_EMOJI = {
    "USDT_TRC20": "💎",
    "USDT":       "💎",
    "TRX":        "⚡",
    "ETH":        "🔷",
    "BTC":        "₿",
}

def normalize_coin(c: str) -> str:
    c = c.upper()
    if c == "USDT": return "USDT_TRC20"
    return c

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

        CREATE TABLE IF NOT EXISTS balances (
            user_id INTEGER,
            coin    TEXT,
            amount  REAL DEFAULT 0,
            PRIMARY KEY (user_id, coin)
        );

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

        CREATE TABLE IF NOT EXISTS wallet_tx (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            type        TEXT,
            coin        TEXT,
            amount      REAL,
            fee         REAL DEFAULT 0,
            counterpart INTEGER,
            tx_hash     TEXT,
            note        TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS deals (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            code            TEXT UNIQUE,
            buyer_id        INTEGER,
            seller_id       INTEGER,
            creator_id      INTEGER,
            amount          REAL,
            coin            TEXT,
            description     TEXT,
            status          TEXT DEFAULT 'confirmed',
            admin_deadline  TEXT,
            chat_id         INTEGER DEFAULT 0,
            created_at      TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS txlog (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_id      INTEGER, type TEXT,
            amount REAL, coin TEXT,
            from_uid     INTEGER, to_uid INTEGER,
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
    coin = normalize_coin(coin)
    row = await one("SELECT amount FROM balances WHERE user_id=? AND coin=?", (user_id, coin))
    return row["amount"] if row else 0.0

async def add_balance(user_id: int, coin: str, amount: float) -> float:
    coin = normalize_coin(coin)
    await exe("""
        INSERT INTO balances(user_id, coin, amount) VALUES(?,?,?)
        ON CONFLICT(user_id, coin) DO UPDATE SET amount = amount + ?
    """, (user_id, coin, amount, amount))
    return await get_balance(user_id, coin)

async def sub_balance(user_id: int, coin: str, amount: float) -> bool:
    coin = normalize_coin(coin)
    bal = await get_balance(user_id, coin)
    if bal < amount - 0.000001:
        return False
    await exe("UPDATE balances SET amount = amount - ? WHERE user_id=? AND coin=?", (amount, user_id, coin))
    return True

async def all_balances(user_id: int) -> Dict[str, float]:
    rows = await many("SELECT coin, amount FROM balances WHERE user_id=? AND amount > 0.000001", (user_id,))
    return {r["coin"]: r["amount"] for r in rows}

async def log_wallet_tx(user_id: int, type_: str, coin: str, amount: float,
                         fee: float = 0, counterpart: int = None,
                         tx_hash: str = None, note: str = None) -> None:
    coin = normalize_coin(coin)
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
    c = normalize_coin(coin)
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
    c = normalize_coin(coin)
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
    c = normalize_coin(coin)
    if c in ("TRX", "USDT_TRC20"):
        return await send_tron(from_addr, privkey, to_addr, amount, c)
    if c == "ETH":
        return await send_eth(privkey, to_addr, amount)
    return None

async def master_send(coin: str, to_addr: str, amount: float) -> Optional[str]:
    c = normalize_coin(coin)
    if c in ("TRX", "USDT_TRC20"):
        return await send_crypto(c, MASTER_TRX_ADDR, MASTER_TRX_KEY, to_addr, amount)
    if c == "ETH":
        return await send_eth(MASTER_ETH_KEY, to_addr, amount)
    return None

# ═══════════════════════════════════════════════════════════
#  YARDIMCILAR
# ═══════════════════════════════════════════════════════════

def gen_code() -> str:
    return secrets.token_hex(6).upper()

def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS

def is_group(msg: Message) -> bool:
    return msg.chat.type in ("group", "supergroup")

def ikb(*rows) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t, callback_data=cb) for t, cb in row]
        for row in rows
    ])

def coin_display(coin: str) -> str:
    c = normalize_coin(coin)
    if c == "USDT_TRC20": return "USDT"
    return c

def fmt_bal(bals: Dict[str, float]) -> str:
    if not bals:
        return "Bakiye yok"
    lines = []
    for c, v in bals.items():
        emoji = COIN_EMOJI.get(c, "💰")
        lines.append(f"  {emoji} {coin_display(c)}: <b>{v:.6f}</b>")
    return "\n".join(lines)

async def ensure_user(user) -> None:
    await exe("INSERT OR REPLACE INTO users(user_id,username,full_name) VALUES(?,?,?)",
              (user.id, user.username or "", user.full_name or ""))

async def get_username(uid: int) -> str:
    row = await one("SELECT username, full_name FROM users WHERE user_id=?", (uid,))
    if row:
        if row["username"]: return f"@{row['username']}"
        if row["full_name"]: return row["full_name"]
    return f"#{uid}"

# ═══════════════════════════════════════════════════════════
#  ESCROW MESAJ FORMATI
# ═══════════════════════════════════════════════════════════

async def format_deal_message(d: Dict) -> str:
    buyer_name  = await get_username(d["buyer_id"])
    seller_name = await get_username(d["seller_id"])
    coin        = coin_display(d["coin"])
    admin_dl    = d.get("admin_deadline", "")[:16] if d.get("admin_deadline") else "—"

    return (
        f"🤝 <b>Ticaret işlem no:</b> {d['code']}\n"
        f"📤 Bu ticaret için {buyer_name} bakiyesi <b>{d['amount']} {coin}</b> azaltıldı.\n\n"
        f"📎 {seller_name} aşağıdaki anlaşma şartlarını yerine getirdiğinde "
        f"{buyer_name} tarafından yatırılan hakedişi alabilecektir:\n"
        f" {seller_name} şu işleri yapacak: <b>{d['description']}</b>\n\n"
        f"  ▪️ Onaylamak için <code>/ticaret onay {d['code']}</code>\n"
        f"  ▪️ İptal etmek için <code>/ticaret iptal {d['code']}</code> komutları kullanılabilir.\n\n"
        f"  ▪️ Bu anlaşmayı tekrar görüntülemek için  <code>/ticaretlerim</code> veya "
        f"<code>/ticaret sorgula {d['code']}</code> komutları kullanabilir.\n\n"
        
    )

# ═══════════════════════════════════════════════════════════
#  FSM STATES
# ═══════════════════════════════════════════════════════════

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
    send_to      = State()
    send_amt     = State()
    broadcast    = State()
    add_bal_uid  = State()
    add_bal_coin = State()
    add_bal_amt  = State()

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
        "🔐 <b> Mswap Wallet & Escrow Botu</b>\n\n"
        "📋 <b>Escrow Komutları:</b>\n"
        "<code>/tic [miktar] [coin] @kullanici [açıklama]</code>\n"
        "<i>Örnek: /tic 24 USDT @kullanici sanal kart</i>\n\n"
        "<code>/ticaret onay [KOD]</code> — Anlaşmayı onayla (teslim aldım)\n"
        "<code>/ticaret iptal [KOD]</code> — Anlaşmayı iptal et\n"
        "<code>/ticaret sorgula [KOD]</code> — Anlaşma detayı\n"
        "<code>/ticaretlerim</code> — Tüm anlaşmalarım\n\n"
        "💰 <b>Cüzdan (sadece DM):</b>\n"
        "/bakiye — Bakiyeni görüntüle\n"
        "/yukle — Kripto bakiye yükle\n"
        "/cek — Kripto çek\n\n"
        "➡️ <b>Transfer (DM ve Grup):</b>\n"
        "<code>/send @kullanici miktar coin</code>\n"
        "<i>Örnek: /send @kullanici 10 TRX</i>\n\n"
        f"💸 Komisyon: %{FEE_PERCENT} | ⏰ Admin onay süresi: {ADMIN_APPROVE_HOURS}s"
    )

@user_r.message(Command("yardim", "help"))
async def cmd_help(msg: Message) -> None:
    await msg.answer(
        "📋 <b>Tüm Komutlar</b>\n\n"
        "<b>Escrow (DM ve Grup):</b>\n"
        "<code>/tic [miktar] [coin] @kullanici [açıklama]</code>\n"
        "<i>Örnek: /tic 24 USDT @kullanici sanal kart</i>\n\n"
        "<code>/ticaret onay KOD</code>\n"
        "<code>/ticaret iptal KOD</code>\n"
        "<code>/ticaret sorgula KOD</code>\n"
        "<code>/ticaretlerim</code>\n\n"
        "<b>Cüzdan (sadece DM):</b>\n"
        "/bakiye — Bakiyeni gör\n"
        "/yukle — Kripto yükle\n"
        "/cek — Kripto çek\n\n"
        "<b>Transfer (DM ve Grup):</b>\n"
        "<code>/gonder @kullanici miktar COIN</code>\n"
        "<code>/send @kullanici miktar COIN</code>\n"
        "<i>Örnek: /send @kullanici 10 TRX</i>\n\n"
    )

# ═══════════════════════════════════════════════════════════
#  /tic — Hızlı escrow
# ═══════════════════════════════════════════════════════════

@user_r.message(Command("tic", "ticaret"))
async def cmd_tic(msg: Message, state: FSMContext, bot: Bot) -> None:
    await ensure_user(msg.from_user)
    uid = msg.from_user.id
    u   = await one("SELECT is_banned FROM users WHERE user_id=?", (uid,))
    if u and u["is_banned"]:
        await msg.answer("🚫 Hesabınız yasaklandı.")
        return

    text = msg.text or ""
    parts = text.split()
    cmd = parts[0].lstrip("/").lower()

    if cmd == "ticaret" and len(parts) >= 2:
        sub = parts[1].lower()
        if sub in ("onay", "iptal", "sorgula"):
            if len(parts) < 3:
                await msg.answer(f"❌ Kullanım: /ticaret {sub} [KOD]")
                return
            code = parts[2].upper()
            await _handle_ticaret_sub(msg, bot, uid, sub, code)
            return

    amount      = None
    coin        = None
    seller_id   = None
    seller_name = None
    desc        = None

    entities = msg.entities or []
    mention  = next((e for e in entities if e.type in ("mention", "text_mention")), None)

    if mention:
        if mention.type == "text_mention":
            seller_id   = mention.user.id
            seller_name = mention.user.full_name or str(mention.user.id)
            await ensure_user(mention.user)
        elif mention.type == "mention":
            uname = text[mention.offset+1:mention.offset+mention.length]
            row   = await one("SELECT user_id, full_name, username FROM users WHERE username=?", (uname,))
            if row:
                seller_id   = row["user_id"]
                seller_name = f"@{uname}"
            else:
                await msg.answer(
                    f"❌ @{uname} kullanıcısı bulunamadı.\n"
                    "Karşı tarafın bota /start yazması gerekiyor."
                )
                return

    non_mention_parts = []
    for i, p in enumerate(parts[1:], 1):
        if p.startswith("@"): continue
        part_offset = sum(len(parts[j]) + 1 for j in range(i))
        is_ment = mention and mention.offset <= part_offset < mention.offset + mention.length
        if not is_ment:
            non_mention_parts.append(p)

    desc_parts = []
    for p in non_mention_parts:
        if amount is None:
            try:
                amount = float(p.replace(",", "."))
                continue
            except ValueError:
                pass
        if coin is None and p.upper() in COINS:
            coin = normalize_coin(p)
            continue
        desc_parts.append(p)

    desc = " ".join(desc_parts).strip() if desc_parts else None

    if not (amount and coin and seller_id and desc):
        await msg.answer(
            "❌ <b>Hatalı kullanım!</b>\n\n"
            "Doğru format:\n"
            "<code>/tic [miktar] [coin] @kullanici [açıklama]</code>\n\n"
            "Desteklenen coinler: USDT, TRX, ETH, BTC\n\n"
            "Örnek:\n"
            "<code>/tic 24 USDT @kullanici saha işlemi</code>\n"
            "<code>/tic 0.5 ETH @kullanici logo tasarımı</code>"
        )
        return

    if seller_id == uid:
        await msg.answer("❌ Kendinizle anlaşma yapamazsınız!")
        return

    bal = await get_balance(uid, coin)
    if bal < amount:
        await msg.answer(
            f"❌ Yetersiz bakiye!\n\n"
            f"Gerekli: <b>{amount} {coin_display(coin)}</b>\n"
            f"Mevcut: <b>{bal:.6f} {coin_display(coin)}</b>\n\n"
            f"/yukle ile bakiye yükleyebilirsiniz."
        )
        return

    ok = await sub_balance(uid, coin, amount)
    if not ok:
        await msg.answer("❌ Bakiye işlemi başarısız, tekrar deneyin.")
        return

    code     = gen_code()
    admin_dl = (datetime.now() + timedelta(hours=ADMIN_APPROVE_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
    chat_id  = msg.chat.id

    deal_id = await exe(
        "INSERT INTO deals(code,buyer_id,seller_id,creator_id,amount,coin,description,status,admin_deadline,chat_id) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        (code, uid, seller_id, uid, amount, coin, desc, "confirmed", admin_dl, chat_id)
    )

    await log_wallet_tx(uid, "escrow_in", coin, amount, note=f"Escrow #{code}")

    d = await one("SELECT * FROM deals WHERE id=?", (deal_id,))
    deal_msg = await format_deal_message(d)

    await msg.answer(deal_msg)

    if is_group(msg):
        try:
            buyer_name = await get_username(uid)
            await bot.send_message(
                seller_id,
                f"📢 <b>Yeni Escrow Anlaşması!</b>\n\n"
                f"Alıcı: {buyer_name}\n"
                f"Tutar: <b>{amount} {coin_display(coin)}</b>\n"
                f"Konu: <b>{desc}</b>\n"
                f"Kod: <code>{code}</code>\n\n"
                f"İşi tamamlayınca alıcıya bildirin, onay versin.\n"
                f"Sorgula: <code>/ticaret sorgula {code}</code>"
            )
        except Exception:
            pass

    log.info("✅ Escrow #%s: buyer=%s seller=%s %s %s", code, uid, seller_id, amount, coin)


async def _handle_ticaret_sub(msg: Message, bot: Bot, uid: int, sub: str, code: str) -> None:
    d = await one("SELECT * FROM deals WHERE code=?", (code,))
    if not d:
        await msg.answer(f"❌ <code>{code}</code> kodlu anlaşma bulunamadı.")
        return

    if sub == "sorgula":
        if uid not in (d["buyer_id"], d["seller_id"]) and not is_admin(uid):
            await msg.answer("❌ Bu anlaşmaya erişim yetkiniz yok.")
            return
        deal_msg = await format_deal_message(d)
        status_txt = {
            "confirmed": "🔐 Devam ediyor",
            "released":  "✅ Tamamlandı",
            "cancelled": "❌ İptal edildi",
            "disputed":  "⚠️ Dispute",
        }.get(d["status"], d["status"])
        await msg.answer(deal_msg + f"\n\n📊 <b>Durum:</b> {status_txt}")
        return

    if sub == "onay":
        if d["status"] != "confirmed":
            await msg.answer(f"❌ Bu anlaşma zaten <b>{d['status']}</b> durumunda.")
            return

        is_group_admin = False
        if is_group(msg) and d.get("chat_id") == msg.chat.id:
            try:
                member = await bot.get_chat_member(msg.chat.id, uid)
                is_group_admin = member.status in ("administrator", "creator")
            except Exception:
                pass
            if is_group_admin:
                deadline = datetime.fromisoformat(d["admin_deadline"]) if d.get("admin_deadline") else None
                if deadline and datetime.now() < deadline:
                    remaining = deadline - datetime.now()
                    hours = int(remaining.total_seconds() / 3600)
                    await msg.answer(
                        f"⏰ Grup yöneticileri <b>{hours} saat</b> sonra onaylayabilir.\n"
                        f"Şu an sadece alıcı onaylayabilir."
                    )
                    return

        if uid != d["buyer_id"] and not is_group_admin and not is_admin(uid):
            await msg.answer("❌ Sadece alıcı veya yetki süresi geçmişse grup yöneticisi onaylayabilir.")
            return

        fee = round(d["amount"] * FEE_PERCENT / 100, 8)
        net = round(d["amount"] - fee, 8)

        await add_balance(d["seller_id"], d["coin"], net)
        await log_wallet_tx(d["buyer_id"],  "escrow_fee", d["coin"], fee,  note=f"Komisyon #{code} → master")
        await log_wallet_tx(d["seller_id"], "escrow_out", d["coin"], net,  counterpart=d["buyer_id"], note=f"Escrow #{code}")

        await exe("UPDATE deals SET status='released' WHERE code=?", (code,))

        buyer_name  = await get_username(d["buyer_id"])
        seller_name = await get_username(d["seller_id"])
        coin_disp   = coin_display(d["coin"])

        await msg.answer(
            f"✅ <b>Anlaşma #{code} Onaylandı!</b>\n\n"
            f"💰 {net:.6f} {coin_disp} → {seller_name}\n"
            f"💸 Komisyon (%{FEE_PERCENT}): {fee:.6f} {coin_disp}\n\n"
            f"🤝 İşlem tamamlandı!"
        )

        try:
            await bot.send_message(
                d["seller_id"],
                f"🎉 <b>Hakediş Ödendi!</b>\n\n"
                f"Anlaşma: <b>#{code}</b>\n"
                f"💰 Net: <b>{net:.6f} {coin_disp}</b>\n"
                f"Bakiyenize eklendi. /bakiye ile görüntüleyin."
            )
        except Exception:
            pass

        for aid in ADMIN_IDS:
            try:
                await bot.send_message(
                    aid,
                    f"✅ <b>Escrow #{code} tamamlandı</b>\n"
                    f"Alıcı: {buyer_name} | Satıcı: {seller_name}\n"
                    f"Net: {net:.6f} {coin_disp} | Komisyon: {fee:.6f}"
                )
            except Exception:
                pass
        return

    if sub == "iptal":
        if d["status"] != "confirmed":
            await msg.answer(f"❌ Bu anlaşma <b>{d['status']}</b> durumunda, iptal edilemez.")
            return
        if uid not in (d["buyer_id"], d["seller_id"]) and not is_admin(uid):
            await msg.answer("❌ Sadece anlaşma tarafları veya adminler iptal edebilir.")
            return

        if uid == d["buyer_id"] or is_admin(uid):
            await add_balance(d["buyer_id"], d["coin"], d["amount"])
            await log_wallet_tx(d["buyer_id"], "escrow_refund", d["coin"], d["amount"], note=f"İptal #{code}")
            await exe("UPDATE deals SET status='cancelled' WHERE code=?", (code,))

            buyer_name  = await get_username(d["buyer_id"])
            seller_name = await get_username(d["seller_id"])

            await msg.answer(
                f"❌ <b>Anlaşma #{code} İptal Edildi</b>\n\n"
                f"💰 {d['amount']} {coin_display(d['coin'])} → {buyer_name} iade edildi."
            )
            try:
                await bot.send_message(
                    d["seller_id"],
                    f"❌ <b>Anlaşma #{code} iptal edildi.</b>\n"
                    f"Alıcı tarafından iptal edildi."
                )
            except Exception:
                pass
        else:
            existing = await cfg_get(f"cancel_req:{code}")
            if existing and existing.get("from") == uid:
                await msg.answer("⏳ İptal talebiniz zaten beklemede.")
                return
            await cfg_set(f"cancel_req:{code}", {"from": uid, "code": code})
            await msg.answer(
                f"📤 İptal talebiniz alıcıya iletildi.\n"
                f"Alıcı <code>/ticaret iptal {code}</code> yazarsa iptal gerçekleşir."
            )
            try:
                await bot.send_message(
                    d["buyer_id"],
                    f"⚠️ <b>Anlaşma #{code} için iptal talebi!</b>\n\n"
                    f"Satıcı anlaşmayı iptal etmek istiyor.\n"
                    f"Kabul etmek için: <code>/ticaret iptal {code}</code>\n"
                    f"Reddetmek için dikkate almayın."
                )
            except Exception:
                pass

# ═══════════════════════════════════════════════════════════
#  /ticaretlerim
# ═══════════════════════════════════════════════════════════

@user_r.message(Command("ticaretlerim"))
async def cmd_ticaretlerim(msg: Message) -> None:
    uid   = msg.from_user.id
    deals = await many(
        "SELECT * FROM deals WHERE buyer_id=? OR seller_id=? ORDER BY created_at DESC LIMIT 10",
        (uid, uid)
    )
    if not deals:
        await msg.answer("📭 Henüz anlaşmanız yok.\n<code>/tic miktar coin @kullanici açıklama</code> ile başlayın.")
        return

    txt = f"📂 <b>Son {len(deals)} Anlaşma:</b>\n\n"
    for d in deals:
        role   = "🛒 Alıcı" if d["buyer_id"] == uid else "🏪 Satıcı"
        status = STATUS_EMOJI.get(d["status"], "❓") + " " + d["status"]
        txt   += (
            f"{role} | <b>#{d['code']}</b>\n"
            f"💰 {d['amount']} {coin_display(d['coin'])} | {status}\n"
            f"📦 {d['description']}\n"
            f"🕐 {d['created_at'][:16]}\n"
            f"<code>/ticaret sorgula {d['code']}</code>\n\n"
        )
    await msg.answer(txt)

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

    txs = await many(
        "SELECT * FROM wallet_tx WHERE user_id=? ORDER BY created_at DESC LIMIT 5",
        (uid,)
    )
    tx_txt = ""
    if txs:
        tx_txt = "\n\n📜 <b>Son İşlemler:</b>\n"
        for t in txs:
            sign  = "+" if t["type"] in ("deposit","receive","escrow_out","escrow_refund") else "-"
            emoji = {
                "deposit":"📥","withdraw":"📤","send":"➡️","receive":"⬅️",
                "escrow_in":"🔐","escrow_out":"💸","escrow_refund":"↩️","escrow_fee":"💸"
            }.get(t["type"], "🔄")
            tx_txt += f"{emoji} {sign}{t['amount']:.6f} {coin_display(t['coin'])} | {t['created_at'][:16]}\n"

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

    disp = coin_display(coin)
    await call.message.edit_text(
        f"📥 <b>{disp} Yükleme Adresi</b>\n\n"
        f"<code>{addr}</code>\n\n"
        f"✅ Bu adrese gönderin — bakiyeniz otomatik yüklenir.\n"
        f"🔄 Kontrol sıklığı: {MONITOR_SEC} saniye\n\n"
        f"⚠️ Sadece <b>{disp}</b> gönderin!"
    )
    await call.answer()

@user_r.callback_query(F.data == "wallet:deposit")
async def wallet_deposit_btn(call: CallbackQuery) -> None:
    if is_group(call.message):
        await call.answer("Sadece DM'de kullanılır.", show_alert=True)
        return
    await call.message.answer(
        "📥 <b>Bakiye Yükle</b>\n\nHangi kripto ile yüklemek istiyorsunuz?",
        reply_markup=ikb(
            [("💎 USDT TRC20", "dep:USDT_TRC20"), ("⚡ TRX", "dep:TRX")],
            [("🔷 ETH",         "dep:ETH"),        ("₿ BTC",  "dep:BTC")]
        )
    )
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
    btns = [(f"{COIN_EMOJI.get(c,'💰')} {coin_display(c)} ({v:.4f})", f"wd_coin:{c}") for c, v in bals.items()]
    rows = [btns[i:i+2] for i in range(0, len(btns), 2)]
    await msg.answer(
        f"📤 <b>Çekim Yap</b>\n⚠️ Komisyon: %{FEE_PERCENT}\n\nHangi coini çekmek istiyorsunuz?",
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
        f"📤 <b>Çekim — {coin_display(coin)}</b>\n\n"
        f"Mevcut bakiye: <b>{bal:.6f} {coin_display(coin)}</b>\n"
        f"Komisyon: %{FEE_PERCENT}\n\n"
        f"Çekmek istediğiniz miktarı yazın:\n"
        f"<i>Tümünü çekmek için: all | İptal: iptal</i>"
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
        f"Göndereceğiniz <b>{coin_display(data['coin'])}</b> adresini girin:"
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
        await msg.answer(f"❌ Geçersiz {coin_display(coin)} adresi. Tekrar girin:")
        return
    await state.update_data(address=addr)
    await state.set_state(WithdrawFSM.confirm)
    fee = round(data["amount"] * FEE_PERCENT / 100, 8)
    net = round(data["amount"] - fee, 8)
    await msg.answer(
        f"📤 <b>Çekim Onayı</b>\n\n"
        f"Coin: <b>{coin_display(coin)}</b>\n"
        f"Miktar: <b>{data['amount']:.6f}</b>\n"
        f"Komisyon (%{FEE_PERCENT}): <b>{fee:.6f}</b>\n"
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
    fee    = round(amount * FEE_PERCENT / 100, 8)
    net    = round(amount - fee, 8)

    ok = await sub_balance(uid, coin, amount)
    if not ok:
        await call.message.edit_text("❌ Yetersiz bakiye.")
        await call.answer()
        return

    await call.message.edit_text(f"⏳ <b>{net:.6f} {coin_display(coin)}</b> gönderiliyor...")
    await call.answer()

    tx = await master_send(coin, addr, net)
    if tx:
        await log_wallet_tx(uid, "withdraw", coin, amount, fee=fee, tx_hash=tx, note=f"→ {addr}")
        await call.message.answer(
            f"✅ <b>Çekim Başarılı!</b>\n\n"
            f"💰 Gönderilen: <b>{net:.6f} {coin_display(coin)}</b>\n"
            f"💸 Komisyon: <b>{fee:.6f}</b> (master cüzdana)\n"
            f"📬 Adres: <code>{addr}</code>\n"
            f"🔗 TX: <code>{tx}</code>"
        )
    else:
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
                    f"Coin: {coin_display(coin)} | Net: {net:.6f}\n"
                    f"Adres: <code>{addr}</code>",
                    reply_markup=ikb([("💸 Manuel Gönder", f"adm_manual_wd:{uid}:{coin}:{net}:{addr}")])
                )
            except Exception:
                pass

@user_r.callback_query(F.data == "wallet:withdraw")
async def wallet_wd_btn(call: CallbackQuery, state: FSMContext) -> None:
    uid  = call.from_user.id
    bals = await all_balances(uid)
    if not bals:
        await call.message.answer("💸 Çekilecek bakiyeniz yok. Önce /yukle ile yükleyin.")
        await call.answer()
        return
    await state.set_state(WithdrawFSM.coin)
    btns = [(f"{COIN_EMOJI.get(c,'💰')} {coin_display(c)} ({v:.4f})", f"wd_coin:{c}") for c, v in bals.items()]
    rows = [btns[i:i+2] for i in range(0, len(btns), 2)]
    await call.message.answer(
        f"📤 <b>Çekim Yap</b>\n⚠️ Komisyon: %{FEE_PERCENT}\n\nHangi coini çekmek istiyorsunuz?",
        reply_markup=ikb(*rows)
    )
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
        sign  = "+" if t["type"] in ("deposit","receive","escrow_out","escrow_refund") else "-"
        emoji = {
            "deposit":"📥","withdraw":"📤","send":"➡️","receive":"⬅️",
            "escrow_in":"🔐","escrow_out":"💸","escrow_refund":"↩️","escrow_fee":"💸"
        }.get(t["type"],"🔄")
        txt += f"{emoji} {sign}{t['amount']:.6f} {coin_display(t['coin'])} | {t['type']} | {t['created_at'][:16]}\n"
    await call.message.edit_text(txt)
    await call.answer()

# ═══════════════════════════════════════════════════════════
#  /send veya /gonder
# ═══════════════════════════════════════════════════════════

@user_r.message(Command("send", "gonder"))
async def cmd_send(msg: Message, state: FSMContext, bot: Bot) -> None:
    await ensure_user(msg.from_user)
    uid = msg.from_user.id
    u   = await one("SELECT is_banned FROM users WHERE user_id=?", (uid,))
    if u and u["is_banned"]:
        await msg.answer("🚫 Hesabınız yasaklandı.")
        return

    text    = msg.text or ""
    mention = msg.entities and next(
        (e for e in msg.entities if e.type in ("mention", "text_mention")), None
    )

    target_id   = None
    target_name = None

    if mention:
        if mention.type == "text_mention":
            target_id   = mention.user.id
            target_name = mention.user.full_name
            await ensure_user(mention.user)
        elif mention.type == "mention":
            uname = text[mention.offset+1:mention.offset+mention.length]
            row   = await one("SELECT user_id, full_name, username FROM users WHERE username=?", (uname,))
            if row:
                target_id   = row["user_id"]
                target_name = f"@{uname}"
            else:
                await msg.answer(
                    f"❌ @{uname} bulunamadı.\n"
                    "Karşı tarafın bota /start yazması gerekiyor."
                )
                return

    args = text.split()[1:]
    amount = None
    coin   = None
    for a in args:
        if a.startswith("@"):
            continue
        if amount is None:
            try:
                amount = float(a.replace(",", "."))
                continue
            except ValueError:
                pass
        if coin is None:
            nc = normalize_coin(a)
            if nc in ("USDT_TRC20", "TRX", "ETH", "BTC"):
                coin = nc
                continue

    if target_id and amount and coin:
        await _do_send(msg, uid, target_id, target_name or str(target_id), coin, amount, bot)
        return

    await msg.answer(
        "➡️ <b>Kripto Gönder</b>\n\n"
        "Kullanım:\n"
        "<code>/send @kullanici miktar COIN</code>\n\n"
        "Örnekler:\n"
        "<code>/send @kullanici 10 TRX</code>\n"
        "<code>/send @kullanici 5 USDT</code>\n"
        "<code>/send @kullanici 0.01 ETH</code>\n\n"
        "Desteklenen coinler: USDT, TRX, ETH, BTC"
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
    btns = [(f"{COIN_EMOJI.get(c,'💰')} {coin_display(c)} ({v:.4f})", f"snd_coin:{c}") for c, v in bals.items()]
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
        f"➡️ Coin: <b>{coin_display(coin)}</b>\n"
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
        f"Coin: <b>{coin_display(data['coin'])}</b>\n"
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
    ok = await sub_balance(from_uid, coin, amount)
    if not ok:
        await msg.answer(f"❌ Yetersiz bakiye. Mevcut: {await get_balance(from_uid, coin):.6f} {coin_display(coin)}")
        return
    await add_balance(to_uid, coin, amount)
    await log_wallet_tx(from_uid, "send",    coin, amount, counterpart=to_uid)
    await log_wallet_tx(to_uid,   "receive", coin, amount, counterpart=from_uid)

    sender_name = (await one("SELECT full_name FROM users WHERE user_id=?", (from_uid,)) or {}).get("full_name", str(from_uid))

    await msg.answer(
        f"✅ <b>Gönderim Başarılı!</b>\n\n"
        f"➡️ {amount:.6f} <b>{coin_display(coin)}</b>\n"
        f"Alıcı: <b>{to_name}</b>"
    )
    if bot:
        try:
            await bot.send_message(
                to_uid,
                f"⬅️ <b>Kripto Aldınız!</b>\n\n"
                f"{amount:.6f} <b>{coin_display(coin)}</b>\n"
                f"Gönderen: <b>{sender_name}</b>\n\n"
                f"/bakiye ile görüntüleyebilirsiniz."
            )
        except Exception:
            pass

@user_r.callback_query(F.data == "close")
async def close_cb(call: CallbackQuery) -> None:
    try: await call.message.delete()
    except: pass
    await call.answer()

# ═══════════════════════════════════════════════════════════
#  ADMİN PANEL
# ═══════════════════════════════════════════════════════════

@admin_r.message(Command("admin"))
async def admin_cmd(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id):
        await msg.answer("🚫 Yetkisiz!"); return
    await state.clear()
    await msg.answer("👑 <b>Admin Paneli</b>", reply_markup=ikb(
        [("📊 Anlaşmalar",      "adm:deals"),     ("⚠️ Disputelar",   "adm:disputes")],
        [("💎 Kullanıcı Bak.",  "adm:wallets"),   ("💸 Fon Gönder",   "adm:send")],
        [("➕ Bakiye Yükle",    "adm:add_bal"),   ("👥 Kullanıcılar", "adm:users")],
        [("📢 Duyuru",          "adm:broadcast"), ("📈 İstatistikler","adm:stats")]
    ))
    await msg.answer(
        "💡 <b>Hızlı Komutlar:</b>\n"
        "<code>/addbal @kullanici miktar coin</code>\n"
        "<i>Örnek: /addbal @ahmet 50 USDT</i>"
    )

@admin_r.callback_query(F.data.startswith("adm:"))
async def admin_cb(call: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True); return
    action = call.data.split(":")[1]

    if action == "wallets":
        rows = await many("SELECT coin, SUM(amount) total FROM balances GROUP BY coin")
        if not rows: await call.message.answer("Kullanıcı bakiyesi yok.")
        else:
            txt = "👛 <b>Toplam Kullanıcı Bakiyeleri</b>\n\n"
            for r in rows:
                txt += f"{COIN_EMOJI.get(r['coin'],'💰')} {coin_display(r['coin'])}: <b>{r['total']:.6f}</b>\n"
            await call.message.answer(txt)

    elif action == "deals":
        await call.message.answer("📊 <b>Filtre:</b>", reply_markup=ikb(
            [("🔐 Devam Eden", "adm_dl:confirmed"), ("✅ Tamamlandı", "adm_dl:released")],
            [("❌ İptal",      "adm_dl:cancelled"), ("⚠️ Dispute",   "adm_dl:disputed")],
            [("📋 Tümü",       "adm_dl:all")]
        ))

    elif action == "disputes":
        deals = await many("SELECT * FROM deals WHERE status='disputed' ORDER BY created_at DESC")
        if not deals: await call.message.answer("✅ Dispute yok.")
        for d in deals:
            buyer_name  = await get_username(d["buyer_id"])
            seller_name = await get_username(d["seller_id"])
            await call.message.answer(
                f"⚠️ <b>Dispute #{d['code']}</b>\n"
                f"Alıcı: {buyer_name} | Satıcı: {seller_name}\n"
                f"💰 {d['amount']} {coin_display(d['coin'])}\n"
                f"📦 {d['description']}",
                reply_markup=ikb(
                    [("✅ Alıcı Haklı (İade)", f"adm_dis_buyer:{d['id']}")],
                    [("✅ Satıcı Haklı (Öde)", f"adm_dis_seller:{d['id']}")]
                )
            )

    elif action == "stats":
        total      = await one("SELECT COUNT(*) c FROM deals")
        released   = await one("SELECT COUNT(*) c FROM deals WHERE status='released'")
        pending    = await one("SELECT COUNT(*) c FROM deals WHERE status='confirmed'")
        disputed   = await one("SELECT COUNT(*) c FROM deals WHERE status='disputed'")
        users      = await one("SELECT COUNT(*) c FROM users")
        tx_count   = await one("SELECT COUNT(*) c FROM wallet_tx")
        fee_earned = await one("SELECT COALESCE(SUM(amount),0) s FROM wallet_tx WHERE type='escrow_fee'")
        await call.message.answer(
            f"📈 <b>İstatistikler</b>\n\n"
            f"👥 Kullanıcı: {users['c']}\n"
            f"📋 Toplam Anlaşma: {total['c']}\n"
            f"🔐 Devam Eden: {pending['c']} | ✅ Tamamlanan: {released['c']}\n"
            f"⚠️ Dispute: {disputed['c']}\n"
            f"💸 Toplam Komisyon: {fee_earned['s']:.6f}\n"
            f"🔄 Cüzdan İşlemi: {tx_count['c']}"
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
        await state.set_state(AdminFSM.send_to)
        await call.message.answer("💸 Hedef adres:")

    elif action == "add_bal":
        await state.set_state(AdminFSM.add_bal_uid)
        await call.message.answer(
            "➕ <b>Kullanıcıya Bakiye Yükle</b>\n\n"
            "Kullanıcının <b>Telegram ID</b>'sini veya <b>@kullanıcıadı</b>'nı girin:"
        )

    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_dl:"))
async def adm_deal_list(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    status = call.data.split(":")[1]
    q = "SELECT * FROM deals ORDER BY created_at DESC LIMIT 15" if status == "all" \
        else "SELECT * FROM deals WHERE status=? ORDER BY created_at DESC LIMIT 15"
    deals = await many(q) if status == "all" else await many(q, (status,))
    if not deals: await call.message.answer("📭 Yok.")
    for d in deals:
        buyer_name  = await get_username(d["buyer_id"])
        seller_name = await get_username(d["seller_id"])
        status_e    = STATUS_EMOJI.get(d["status"],"❓")
        await call.message.answer(
            f"{status_e} <b>#{d['code']}</b>\n"
            f"Alıcı: {buyer_name} | Satıcı: {seller_name}\n"
            f"💰 {d['amount']} {coin_display(d['coin'])}\n"
            f"📦 {d['description']}\n"
            f"🕐 {d['created_at'][:16]}",
            reply_markup=ikb([("🔧 Yönet", f"adm_mgmt:{d['id']}")])
        )
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_mgmt:"))
async def adm_mgmt(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d: await call.answer("Yok",show_alert=True); return
    btns = []
    if d["status"] == "confirmed":
        btns.append([("✅ Zorla Onayla (Satıcıya öde)", f"adm_force_ok:{did}")])
        btns.append([("❌ İptal Et (Alıcıya iade)",     f"adm_force_cancel:{did}")])
        btns.append([("⚠️ Dispute Aç",                  f"adm_force_dispute:{did}")])
    buyer_name  = await get_username(d["buyer_id"])
    seller_name = await get_username(d["seller_id"])
    await call.message.answer(
        f"🔧 <b>Yönet #{d['code']}</b>\n"
        f"Alıcı: {buyer_name} | Satıcı: {seller_name}\n"
        f"💰 {d['amount']} {coin_display(d['coin'])} | {d['status']}",
        reply_markup=ikb(*btns) if btns else None
    )
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_force_ok:"))
async def adm_force_ok(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d: return
    fee = round(d["amount"] * FEE_PERCENT / 100, 8)
    net = round(d["amount"] - fee, 8)
    await add_balance(d["seller_id"], d["coin"], net)
    await log_wallet_tx(d["seller_id"], "escrow_out", d["coin"], net, counterpart=d["buyer_id"], note=f"Admin onay #{d['code']}")
    await log_wallet_tx(d["buyer_id"],  "escrow_fee", d["coin"], fee, note=f"Komisyon #{d['code']}")
    await exe("UPDATE deals SET status='released' WHERE id=?", (did,))
    try: await call.message.edit_text(f"✅ #{d['code']} onaylandı. {net:.6f} {coin_display(d['coin'])} satıcıya eklendi.")
    except: pass
    try:
        await bot.send_message(d["seller_id"],
            f"🎉 <b>Hakediş Ödendi (Admin Onayı)!</b>\n\n"
            f"Anlaşma: #{d['code']}\n💰 {net:.6f} {coin_display(d['coin'])}\n/bakiye ile görüntüleyin.")
    except: pass
    try:
        await bot.send_message(d["buyer_id"],
            f"✅ Anlaşma #{d['code']} admin tarafından onaylandı.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_force_cancel:"))
async def adm_force_cancel(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d: return
    await add_balance(d["buyer_id"], d["coin"], d["amount"])
    await log_wallet_tx(d["buyer_id"], "escrow_refund", d["coin"], d["amount"], note=f"Admin iptal #{d['code']}")
    await exe("UPDATE deals SET status='cancelled' WHERE id=?", (did,))
    try: await call.message.edit_text(f"❌ #{d['code']} iptal. {d['amount']} {coin_display(d['coin'])} alıcıya iade.")
    except: pass
    for uid in [d["buyer_id"], d["seller_id"]]:
        try: await bot.send_message(uid, f"❌ Anlaşma #{d['code']} admin tarafından iptal edildi.")
        except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_force_dispute:"))
async def adm_force_dispute(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    await exe("UPDATE deals SET status='disputed' WHERE id=?", (did,))
    try: await call.message.edit_text("⚠️ Dispute işaretlendi.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_dis_buyer:"))
async def adm_dis_buyer(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    await add_balance(d["buyer_id"], d["coin"], d["amount"])
    await log_wallet_tx(d["buyer_id"], "escrow_refund", d["coin"], d["amount"], note=f"Dispute iade #{d['code']}")
    await exe("UPDATE deals SET status='cancelled' WHERE id=?", (did,))
    try: await bot.send_message(d["buyer_id"], f"✅ Dispute: Haklı bulundunuz. #{d['code']} iade edildi.")
    except: pass
    try: await bot.send_message(d["seller_id"], f"⚠️ Dispute: Alıcı haklı bulundu. #{d['code']}")
    except: pass
    try: await call.message.edit_text("✅ Alıcı lehine çözüldü.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_dis_seller:"))
async def adm_dis_seller(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    fee = round(d["amount"] * FEE_PERCENT / 100, 8)
    net = round(d["amount"] - fee, 8)
    await add_balance(d["seller_id"], d["coin"], net)
    await log_wallet_tx(d["seller_id"], "escrow_out", d["coin"], net, note=f"Dispute karar #{d['code']}")
    await log_wallet_tx(d["buyer_id"],  "escrow_fee", d["coin"], fee, note=f"Komisyon #{d['code']}")
    await exe("UPDATE deals SET status='released' WHERE id=?", (did,))
    try: await bot.send_message(d["seller_id"], f"✅ Dispute: Haklı bulundunuz! {net:.6f} {coin_display(d['coin'])} bakiyenize eklendi.")
    except: pass
    try: await bot.send_message(d["buyer_id"], f"⚠️ Dispute: Satıcı haklı bulundu. #{d['code']}")
    except: pass
    try: await call.message.edit_text("✅ Satıcı lehine çözüldü.")
    except: pass
    await call.answer()

@admin_r.callback_query(F.data.startswith("adm_manual_wd:"))
async def adm_manual_wd(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫",show_alert=True); return
    parts  = call.data.split(":")
    uid    = int(parts[1])
    coin   = parts[2]
    amount = float(parts[3])
    addr   = parts[4]
    await call.message.answer(f"⏳ Manuel çekim: {amount} {coin_display(coin)} → {addr}")
    tx = await master_send(coin, addr, amount)
    if tx:
        await log_wallet_tx(uid, "withdraw", coin, amount, tx_hash=tx, note=f"Admin manuel → {addr}")
        await call.message.answer(f"✅ Gönderildi! TX: <code>{tx}</code>")
        try: await bot.send_message(uid, f"✅ Çekim tamamlandı!\n{amount} {coin_display(coin)} → <code>{addr}</code>\nTX: <code>{tx}</code>")
        except: pass
    else:
        await call.message.answer("❌ Gönderim başarısız. Manuel işlem gerekiyor.")
    await call.answer()

@admin_r.message(StateFilter(AdminFSM.send_to))
async def adm_send_to(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id): return
    await state.update_data(send_to=msg.text.strip())
    await state.set_state(AdminFSM.send_amt)
    await msg.answer("💰 Coin:Miktar (örnek: USDT_TRC20:10.5):")

@admin_r.message(StateFilter(AdminFSM.send_amt))
async def adm_send_amt(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id): return
    try:
        coin_str, amt_str = msg.text.strip().split(":")
        coin   = normalize_coin(coin_str.strip())
        amount = float(amt_str.strip())
    except:
        await msg.answer("❌ Format: USDT_TRC20:10.5")
        return
    data = await state.get_data()
    await state.clear()
    await msg.answer(f"⏳ {amount} {coin_display(coin)} → {data['send_to']} gönderiliyor...")
    tx = await master_send(coin, data["send_to"], amount)
    if tx:
        await msg.answer(f"✅ TX: <code>{tx}</code>")
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

@admin_r.message(StateFilter(AdminFSM.add_bal_uid))
async def adm_add_bal_uid(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id): return
    text = msg.text.strip()
    if text.lower() == "iptal":
        await state.clear(); await msg.answer("❌ İptal."); return

    target_id = None
    mention = msg.entities and next(
        (e for e in msg.entities if e.type in ("mention", "text_mention")), None
    )
    if mention:
        if mention.type == "text_mention":
            target_id = mention.user.id
        elif mention.type == "mention":
            uname = text[mention.offset+1:mention.offset+mention.length]
            row   = await one("SELECT user_id FROM users WHERE username=?", (uname,))
            if row: target_id = row["user_id"]
    elif text.startswith("@"):
        row = await one("SELECT user_id FROM users WHERE username=?", (text[1:],))
        if row: target_id = row["user_id"]
    else:
        try: target_id = int(text)
        except ValueError: pass

    if not target_id:
        await msg.answer("❌ Kullanıcı bulunamadı. ID veya @kullanıcıadı girin:"); return

    u = await one("SELECT user_id FROM users WHERE user_id=?", (target_id,))
    if not u:
        await exe("INSERT OR IGNORE INTO users(user_id) VALUES(?)", (target_id,))

    await state.update_data(target_id=target_id)
    await state.set_state(AdminFSM.add_bal_coin)
    await msg.answer(
        f"✅ Kullanıcı: <code>{target_id}</code>\n\n"
        f"Hangi coinden yüklemek istiyorsunuz?",
        reply_markup=ikb(
            [("💎 USDT TRC20", "adm_bal_coin:USDT_TRC20"), ("⚡ TRX", "adm_bal_coin:TRX")],
            [("🔷 ETH",        "adm_bal_coin:ETH"),         ("₿ BTC",  "adm_bal_coin:BTC")]
        )
    )

@admin_r.callback_query(F.data.startswith("adm_bal_coin:"), StateFilter(AdminFSM.add_bal_coin))
async def adm_add_bal_coin(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id): await call.answer("🚫", show_alert=True); return
    coin = call.data.split(":")[1]
    await state.update_data(coin=coin)
    await state.set_state(AdminFSM.add_bal_amt)
    data = await state.get_data()
    await call.message.edit_text(
        f"✅ Coin: <b>{coin_display(coin)}</b>\n"
        f"Kullanıcı: <code>{data['target_id']}</code>\n\n"
        f"Yüklenecek miktarı girin:"
    )
    await call.answer()

@admin_r.message(StateFilter(AdminFSM.add_bal_amt))
async def adm_add_bal_amt(msg: Message, state: FSMContext, bot: Bot) -> None:
    if not is_admin(msg.from_user.id): return
    if msg.text.strip().lower() == "iptal":
        await state.clear(); await msg.answer("❌ İptal."); return
    try:
        amount = float(msg.text.strip().replace(",", "."))
        if amount <= 0: raise ValueError
    except ValueError:
        await msg.answer("❌ Geçersiz miktar. Pozitif sayı girin:"); return

    data = await state.get_data()
    await state.clear()

    target_id = data["target_id"]
    coin      = data["coin"]

    new_bal = await add_balance(target_id, coin, amount)
    await log_wallet_tx(target_id, "deposit", coin, amount, note="Admin tarafından yüklendi")

    await msg.answer(
        f"✅ <b>Bakiye Yüklendi!</b>\n\n"
        f"👤 Kullanıcı: <code>{target_id}</code>\n"
        f"💰 Yüklenen: <b>+{amount} {coin_display(coin)}</b>\n"
        f"📊 Yeni bakiye: <b>{new_bal:.6f} {coin_display(coin)}</b>"
    )

    try:
        await bot.send_message(
            target_id,
            f"📥 <b>Bakiyenize Yükleme Yapıldı!</b>\n\n"
            f"💰 +{amount} <b>{coin_display(coin)}</b>\n"
            f"📊 Yeni bakiye: <b>{new_bal:.6f} {coin_display(coin)}</b>\n\n"
            f"/bakiye ile görüntüleyebilirsiniz."
        )
    except Exception:
        pass

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

@admin_r.message(Command("addbal"))
async def cmd_addbal(msg: Message, bot: Bot) -> None:
    if not is_admin(msg.from_user.id):
        await msg.answer("🚫 Yetkisiz!")
        return

    text  = msg.text or ""
    parts = text.split()

    mention = msg.entities and next(
        (e for e in msg.entities if e.type in ("mention", "text_mention")), None
    )

    target_id = None
    amount    = None
    coin      = None

    if mention:
        if mention.type == "text_mention":
            target_id = mention.user.id
            await ensure_user(mention.user)
        elif mention.type == "mention":
            uname = text[mention.offset+1:mention.offset+mention.length]
            row   = await one("SELECT user_id FROM users WHERE username=?", (uname,))
            if row:
                target_id = row["user_id"]

    non_mention = [p for p in parts[1:] if not p.startswith("@")]
    for p in non_mention:
        if target_id is None:
            try:
                target_id = int(p)
                continue
            except ValueError:
                pass
        if amount is None:
            try:
                amount = float(p.replace(",", "."))
                continue
            except ValueError:
                pass
        if coin is None:
            nc = normalize_coin(p)
            if nc in ("USDT_TRC20", "TRX", "ETH", "BTC"):
                coin = nc

    if not (target_id and amount and coin):
        await msg.answer(
            "❌ <b>Hatalı kullanım!</b>\n\n"
            "Format: <code>/addbal @kullanici miktar coin</code>\n"
            "Veya:   <code>/addbal TelegramID miktar coin</code>\n\n"
            "Örnek:\n"
            "<code>/addbal @ahmet 50 USDT</code>\n"
            "<code>/addbal 123456789 0.5 ETH</code>"
        )
        return

    if amount <= 0:
        await msg.answer("❌ Miktar 0'dan büyük olmalı.")
        return

    u = await one("SELECT user_id FROM users WHERE user_id=?", (target_id,))
    if not u:
        await exe("INSERT OR IGNORE INTO users(user_id) VALUES(?)", (target_id,))

    new_bal = await add_balance(target_id, coin, amount)
    await log_wallet_tx(target_id, "deposit", coin, amount, note=f"Admin yükledi ({msg.from_user.id})")

    await msg.answer(
        f"✅ <b>Bakiye Yüklendi!</b>\n\n"
        f"👤 Kullanıcı: <code>{target_id}</code>\n"
        f"💰 Yüklenen: <b>+{amount} {coin_display(coin)}</b>\n"
        f"📊 Yeni bakiye: <b>{new_bal:.6f} {coin_display(coin)}</b>"
    )

    try:
        await bot.send_message(
            target_id,
            f"📥 <b>Bakiyenize Yükleme Yapıldı!</b>\n\n"
            f"💰 +{amount} <b>{coin_display(coin)}</b>\n"
            f"📊 Yeni bakiye: <b>{new_bal:.6f} {coin_display(coin)}</b>\n\n"
            f"/bakiye ile görüntüleyebilirsiniz."
        )
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════
#  MONİTÖR — Bakiye yükleme
# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
#  SWEEP — Kullanıcı adreslerinden master'a otomatik transfer
# ═══════════════════════════════════════════════════════════

# TRX işlem ücreti için adreste bırakılacak minimum miktar
TRX_FEE_RESERVE  = float(os.getenv("TRX_FEE_RESERVE",  "2.0"))   # 2 TRX gas için
ETH_FEE_RESERVE  = float(os.getenv("ETH_FEE_RESERVE",  "0.002")) # 0.002 ETH gas için

async def sweep_trx(addr: str, privkey: str, amount: float) -> Optional[str]:
    """TRX bakiyesini master adrese gönder (gas rezervi bırak)"""
    sweep_amount = amount - TRX_FEE_RESERVE
    if sweep_amount <= 0.001:
        return None
    return await send_tron(addr, privkey, MASTER_TRX_ADDR, sweep_amount, "TRX")

async def sweep_usdt(addr: str, privkey: str, amount: float) -> Optional[str]:
    """USDT TRC20 bakiyesini master adrese gönder"""
    if amount <= 0.01:
        return None
    # USDT göndermek için TRX gas gerekir, önce TRX bakiyesi kontrol et
    trx_bal = await chain_bal_trx(addr)
    if trx_bal < TRX_FEE_RESERVE:
        # Gas için master'dan TRX gönder
        log.info("🔋 %s için gas TRX gönderiliyor...", addr)
        gas_tx = await send_tron(MASTER_TRX_ADDR, MASTER_TRX_KEY, addr, TRX_FEE_RESERVE, "TRX")
        if gas_tx:
            await asyncio.sleep(5)  # zincirin işlemesi için bekle
        else:
            log.warning("Gas TRX gönderilemedi: %s", addr)
            return None
    return await send_tron(addr, privkey, MASTER_TRX_ADDR, amount, "USDT_TRC20")

async def sweep_eth(addr: str, privkey: str, amount: float) -> Optional[str]:
    """ETH bakiyesini master adrese gönder (gas rezervi bırak)"""
    sweep_amount = amount - ETH_FEE_RESERVE
    if sweep_amount <= 0.0001:
        return None
    return await send_eth(privkey, MASTER_ETH_ADDR, sweep_amount)

async def sweep_to_master(coin: str, addr: str, privkey: str, amount: float) -> Optional[str]:
    """Coin türüne göre uygun sweep fonksiyonunu çağır"""
    c = normalize_coin(coin)
    try:
        if c == "TRX":
            return await sweep_trx(addr, privkey, amount)
        if c == "USDT_TRC20":
            return await sweep_usdt(addr, privkey, amount)
        if c == "ETH":
            return await sweep_eth(addr, privkey, amount)
    except Exception as e:
        log.error("Sweep hatası %s %s: %s", coin, addr, e)
    return None

async def deposit_monitor(bot: Bot) -> None:
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
                        total = await add_balance(a["user_id"], a["coin"], new_amount)
                        await log_wallet_tx(a["user_id"], "deposit", a["coin"], new_amount)
                        log.info("💰 Deposit: user=%s +%s %s", a["user_id"], new_amount, a["coin"])

                        # ── Kullanıcıya bildir ──
                        try:
                            await bot.send_message(
                                a["user_id"],
                                f"📥 <b>Bakiye Yüklendi!</b>\n\n"
                                f"💰 +{new_amount:.6f} {coin_display(a['coin'])}\n"
                                f"📊 Toplam bakiye: <b>{total:.6f} {coin_display(a['coin'])}</b>\n\n"
                                f"/bakiye ile görüntüleyebilirsiniz."
                            )
                        except Exception: pass

                        # ── Master cüzdana sweep et ──
                        asyncio.create_task(
                            _do_sweep(bot, a["coin"], a["address"], a["privkey"], bal, a["id"])
                        )

                except Exception as e:
                    log.warning("Deposit monitor hata: %s", e)
        except Exception as e:
            log.error("Deposit monitor kritik: %s", e)
        await asyncio.sleep(MONITOR_SEC)


async def _do_sweep(bot: Bot, coin: str, addr: str, privkey: str, amount: float, dep_id: int) -> None:
    """Arka planda sweep işlemi yap ve logla"""
    await asyncio.sleep(10)  # zincir onayı için kısa bekle
    log.info("🔄 Sweep başlıyor: %s %s → master", amount, coin)
    tx = await sweep_to_master(coin, addr, privkey, amount)
    if tx:
        log.info("✅ Sweep OK: %s → master | TX: %s", coin, tx)
        await exe(
            "INSERT INTO wallet_tx(user_id,type,coin,amount,tx_hash,note) VALUES(?,?,?,?,?,?)",
            (0, "sweep", normalize_coin(coin), amount, tx, f"dep_id:{dep_id} → master")
        )
        # Adminlere bilgi ver (opsiyonel, sessiz hata)
        for aid in ADMIN_IDS:
            try:
                await bot.send_message(
                    aid,
                    f"🔄 <b>Sweep Tamamlandı</b>\n"
                    f"💰 {amount:.6f} {coin_display(coin)}\n"
                    f"📬 Master: <code>{'MASTER_TRX_ADDR' if normalize_coin(coin) in ('TRX','USDT_TRC20') else 'MASTER_ETH_ADDR'}</code>\n"
                    f"🔗 TX: <code>{tx}</code>"
                )
            except Exception:
                pass
    else:
        log.warning("⚠️ Sweep başarısız: %s %s (miktar çok küçük veya gas yetersiz)", coin, addr)

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

    asyncio.create_task(deposit_monitor(bot))

    log.info("🤖 Escrow+Wallet Bot v5.0 | Admin: %s | Fee: %.1f%%", ADMIN_IDS, FEE_PERCENT)
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())


if __name__ == "__main__":
    print("╔══════════════════════════════════════════╗")
    print("║   Escrow + Wallet Bot v5.0               ║")
    print("╠══════════════════════════════════════════╣")
    print("║ ENV değişkenleri:                        ║")
    print("║  BOT_TOKEN          — Telegram bot token ║")
    print("║  ADMIN_IDS          — 123,456 formatında ║")
    print("║  FEE_PERCENT        — varsayılan: 4.0    ║")
    print("║  MASTER_TRX_ADDR / MASTER_TRX_KEY        ║")
    print("║  MASTER_ETH_ADDR / MASTER_ETH_KEY        ║")
    print("║  TRON_API_KEY (opsiyonel)                ║")
    print("║  ADMIN_APPROVE_HOURS — varsayılan: 72    ║")
    print("╚══════════════════════════════════════════╝")
    asyncio.run(main())
