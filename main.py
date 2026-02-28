#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Escrow Bot v3.0 — Production Ready
pip install aiogram==3.7.0 aiosqlite aiohttp tronpy eth-account
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
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
)

# ═══════════════════════════════════════════════════════════════════
#  YAPILANDIRMA  ← BURADAN DEĞİŞTİR
# ═══════════════════════════════════════════════════════════════════
BOT_TOKEN     = os.getenv("BOT_TOKEN",    "8698709943:AAE3ZVzjyMSE9elndQCJo-9dVTWsgG41ABY")
ADMIN_IDS     = [int(x) for x in os.getenv("ADMIN_IDS", "7672180974").split(",") if x.strip()]
DB_PATH       = os.getenv("DB_PATH",      "escrow.db")
FEE_PERCENT   = float(os.getenv("FEE_PERCENT",   "2.0"))
PAYMENT_HOURS = int(os.getenv("PAYMENT_HOURS",   "24"))
MONITOR_SEC   = int(os.getenv("MONITOR_SEC",     "30"))
TRON_API_KEY  = os.getenv("TRON_API_KEY", "")
# ═══════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
log = logging.getLogger("escrow")

USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

COINS: Dict[str, str] = {
    "USDT_TRC20": "💎 USDT (TRC20)",
    "TRX":        "⚡ TRX",
    "ETH":        "🔷 ETH",
    "BTC":        "₿ BTC",
}

STATUS_EMOJI: Dict[str, str] = {
    "pending":         "⏳",
    "payment_pending": "💳",
    "confirmed":       "🔐",
    "released":        "💸",
    "cancelled":       "❌",
    "disputed":        "⚠️",
}

# ═══════════════════════════════════════════════════════════════════
#  VERİTABANI
# ═══════════════════════════════════════════════════════════════════

async def db_init() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id    INTEGER PRIMARY KEY,
            username   TEXT DEFAULT '',
            full_name  TEXT DEFAULT '',
            is_banned  INTEGER DEFAULT 0,
            deal_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );

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

        CREATE TABLE IF NOT EXISTS iban_pay (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_id      INTEGER,
            iban         TEXT,
            bank         TEXT,
            holder       TEXT,
            amount       REAL,
            currency     TEXT,
            status       TEXT DEFAULT 'waiting',
            admin_id     INTEGER,
            confirmed_at TEXT,
            created_at   TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS txlog (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            deal_id      INTEGER,
            type         TEXT,
            amount       REAL,
            currency     TEXT,
            from_address TEXT,
            to_address   TEXT,
            tx_hash      TEXT,
            note         TEXT,
            created_at   TEXT DEFAULT (datetime('now'))
        );
        """)
        await db.commit()


async def cfg_get(key: str, default=None):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT value FROM settings WHERE key=?", (key,)) as c:
            row = await c.fetchone()
            if row:
                try:
                    return json.loads(row[0])
                except Exception:
                    return row[0]
            return default


async def cfg_set(key: str, value) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
            (key, json.dumps(value))
        )
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

# ═══════════════════════════════════════════════════════════════════
#  CÜZDAN ÜRETİCİ
# ═══════════════════════════════════════════════════════════════════

def gen_tron() -> Tuple[str, str]:
    try:
        from tronpy.keys import PrivateKey
        pk = PrivateKey(secrets.token_bytes(32))
        return pk.public_key.to_base58check_address(), pk.hex()
    except Exception:
        priv = secrets.token_hex(32)
        raw  = hashlib.sha256(bytes.fromhex(priv)).digest()
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


def generate_address(coin: str) -> Tuple[str, str]:
    c = coin.upper()
    if c in ("TRX", "USDT_TRC20"):
        return gen_tron()
    if c in ("ETH", "USDT_ERC20"):
        return gen_eth()
    if c == "BTC":
        return gen_btc()
    raise ValueError(f"Bilinmeyen coin: {coin}")

# ═══════════════════════════════════════════════════════════════════
#  BLOCKCHAIN BAKIYE
# ═══════════════════════════════════════════════════════════════════

async def _http_get(url: str, headers: dict = None) -> dict:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(
                url,
                headers=headers or {},
                timeout=aiohttp.ClientTimeout(total=12)
            ) as r:
                return await r.json(content_type=None)
    except Exception as e:
        log.warning("HTTP GET error %s: %s", url, e)
        return {}


async def bal_trx(address: str) -> float:
    h = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}
    d = await _http_get(f"https://api.trongrid.io/v1/accounts/{address}", h)
    return d.get("data", [{}])[0].get("balance", 0) / 1_000_000


async def bal_usdt_trc20(address: str) -> float:
    h = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}
    d = await _http_get(f"https://api.trongrid.io/v1/accounts/{address}/tokens", h)
    for t in d.get("data", []):
        if t.get("tokenId") == USDT_TRC20_CONTRACT or t.get("tokenAbbr") == "USDT":
            return float(t.get("balance", 0)) / 1_000_000
    return 0.0


async def bal_eth(address: str) -> float:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                "https://cloudflare-eth.com",
                json={"jsonrpc": "2.0", "method": "eth_getBalance",
                      "params": [address, "latest"], "id": 1},
                timeout=aiohttp.ClientTimeout(total=12)
            ) as r:
                d = await r.json()
                return int(d.get("result", "0x0"), 16) / 1e18
    except Exception:
        return 0.0


async def bal_btc(address: str) -> float:
    d  = await _http_get(f"https://blockstream.info/api/address/{address}")
    cs = d.get("chain_stats", {})
    return (cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)) / 1e8


async def get_balance(coin: str, address: str) -> float:
    c = coin.upper()
    if c == "TRX":
        return await bal_trx(address)
    if c == "USDT_TRC20":
        return await bal_usdt_trc20(address)
    if c == "ETH":
        return await bal_eth(address)
    if c == "BTC":
        return await bal_btc(address)
    return 0.0

# ═══════════════════════════════════════════════════════════════════
#  KRİPTO GÖNDERME
# ═══════════════════════════════════════════════════════════════════

async def send_tron(
    from_addr: str, privkey: str,
    to_addr: str, amount: float, coin: str
) -> Optional[str]:
    try:
        from tronpy import Tron
        from tronpy.keys import PrivateKey
        from tronpy.providers import HTTPProvider
        provider = HTTPProvider(api_key=TRON_API_KEY) if TRON_API_KEY else None
        client   = Tron(provider=provider)
        pk       = PrivateKey(bytes.fromhex(privkey))
        if coin == "TRX":
            txn = (
                client.trx.transfer(from_addr, to_addr, int(amount * 1_000_000))
                .memo("Escrow payout")
                .build()
                .sign(pk)
            )
        else:
            contract = client.get_contract(USDT_TRC20_CONTRACT)
            txn = (
                contract.functions.transfer(to_addr, int(amount * 1_000_000))
                .with_owner(from_addr)
                .fee_limit(20_000_000)
                .build()
                .sign(pk)
            )
        res = txn.broadcast().wait()
        return res.get("id") or res.get("txid")
    except Exception as e:
        log.error("Tron send error: %s", e)
        return None


async def send_eth(privkey: str, to_addr: str, amount: float) -> Optional[str]:
    try:
        from eth_account import Account
        from web3 import Web3
        w3   = Web3(Web3.HTTPProvider("https://cloudflare-eth.com"))
        acct = Account.from_key(privkey)
        tx   = {
            "to":       to_addr,
            "value":    w3.to_wei(amount, "ether"),
            "gas":      21000,
            "gasPrice": w3.eth.gas_price,
            "nonce":    w3.eth.get_transaction_count(acct.address),
            "chainId":  1,
        }
        signed = acct.sign_transaction(tx)
        return w3.eth.send_raw_transaction(signed.rawTransaction).hex()
    except Exception as e:
        log.error("ETH send error: %s", e)
        return None

# ═══════════════════════════════════════════════════════════════════
#  YARDIMCILAR
# ═══════════════════════════════════════════════════════════════════

def gen_code() -> str:
    return secrets.token_hex(4).upper()


def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS


def deal_text(d: Dict) -> str:
    emoji = STATUS_EMOJI.get(d["status"], "❓")
    return (
        f"{emoji} <b>Anlaşma #{d['code']}</b>\n"
        f"💰 {d['amount']} {d['currency']}\n"
        f"📦 {d['description']}\n"
        f"💳 {d.get('method', '—')}\n"
        f"📊 Durum: <b>{d['status']}</b>\n"
        f"📅 {d['created_at'][:16]}"
    )


def ikb(*rows) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t, callback_data=cb) for t, cb in row]
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


CANCEL_KB = ReplyKeyboardMarkup(
    keyboard=[[KeyboardButton(text="❌ İptal")]],
    resize_keyboard=True
)

# ═══════════════════════════════════════════════════════════════════
#  FSM STATES
# ═══════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════
#  ROUTERLAR
# ═══════════════════════════════════════════════════════════════════

user_r  = Router()
admin_r = Router()

# ═══════════════════════════════════════════════════════════════════
#  KULLANICI — GENEL KOMUTLAR
# ═══════════════════════════════════════════════════════════════════

@user_r.message(CommandStart())
async def cmd_start(msg: Message, state: FSMContext) -> None:
    await state.clear()
    await exe(
        "INSERT OR REPLACE INTO users(user_id,username,full_name) VALUES(?,?,?)",
        (msg.from_user.id, msg.from_user.username or "", msg.from_user.full_name or "")
    )
    u = await one("SELECT is_banned FROM users WHERE user_id=?", (msg.from_user.id,))
    if u and u["is_banned"]:
        await msg.answer("🚫 Hesabınız yasaklandı. Destek için yönetici ile iletişime geçin.")
        return
    await msg.answer(
        "🔐 <b>Escrow Bot'a Hoş Geldiniz!</b>\n\n"
        "Alıcı ve satıcı arasında güvenli ödeme aracılığı sağlıyoruz.\n"
        "Para önce bot tarafından tutulur, teslim onayından sonra satıcıya aktarılır.\n\n"
        f"💸 Komisyon: <b>%{FEE_PERCENT}</b>\n"
        f"⏰ Ödeme süresi: <b>{PAYMENT_HOURS} saat</b>",
        reply_markup=main_kb(msg.from_user.id)
    )


@user_r.message(F.text == "ℹ️ Nasıl Çalışır")
async def how_works(msg: Message) -> None:
    await msg.answer(
        "📖 <b>Nasıl Çalışır?</b>\n\n"
        "1️⃣ <b>Anlaşma Oluştur</b> — Karşı tarafın ID'sini gir, rolünü seç\n\n"
        "2️⃣ <b>Ödeme Yap</b>\n"
        "   • 🏦 IBAN: Admin hesabına havale → Admin onaylar\n"
        "   • 💎 Kripto: Verilen adrese gönder → Otomatik doğrulanır\n\n"
        "3️⃣ <b>Teslim Al & Onayla</b>\n"
        "   • Ürün/hizmeti al → Teslim onayı ver\n"
        "   • Para satıcıya aktarılır\n\n"
        "⚠️ <b>Sorun varsa?</b> Dispute aç, admin çözer.\n\n"
        f"💸 Komisyon: %{FEE_PERCENT} | ⏰ Süre: {PAYMENT_HOURS} saat"
    )


@user_r.message(F.text == "💬 Destek")
async def support(msg: Message) -> None:
    await msg.answer(
        "💬 <b>Destek</b>\n\n"
        "Sorun veya şikayetleriniz için admin ile iletişime geçin.\n"
        "Aktif anlaşmalarınızda dispute açabilirsiniz."
    )

# ═══════════════════════════════════════════════════════════════════
#  ANLAŞMALARıM
# ═══════════════════════════════════════════════════════════════════

@user_r.message(F.text == "📂 Anlaşmalarım")
async def my_deals(msg: Message) -> None:
    uid   = msg.from_user.id
    deals = await many(
        "SELECT * FROM deals WHERE buyer_id=? OR seller_id=? ORDER BY created_at DESC LIMIT 10",
        (uid, uid)
    )
    if not deals:
        await msg.answer("📭 Henüz hiç anlaşmanız yok.", reply_markup=main_kb(uid))
        return
    await msg.answer(f"📂 <b>Son {len(deals)} Anlaşma:</b>")
    for d in deals:
        role = "🛒 Alıcı" if d["buyer_id"] == uid else "🏪 Satıcı"
        btns = []
        if d["status"] == "payment_pending":
            btns.append([("💳 Ödeme Bilgisi", f"pay_info:{d['id']}")])
        if d["status"] == "confirmed" and d["buyer_id"] == uid:
            btns.append([
                ("✅ Teslim Aldım", f"release:{d['id']}"),
                ("⚠️ Dispute Aç",   f"dispute:{d['id']}")
            ])
        btns.append([("🔍 Detay", f"detail:{d['id']}")])
        await msg.answer(f"👤 {role}\n\n{deal_text(d)}", reply_markup=ikb(*btns))


@user_r.callback_query(F.data.startswith("detail:"))
async def deal_detail(call: CallbackQuery) -> None:
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d:
        await call.answer("Bulunamadı", show_alert=True)
        return
    uid = call.from_user.id
    if uid not in (d["buyer_id"], d["seller_id"]) and not is_admin(uid):
        await call.answer("❌ Yetkisiz", show_alert=True)
        return
    extra = ""
    if d["method"] == "IBAN":
        ip = await one(
            "SELECT * FROM iban_pay WHERE deal_id=? ORDER BY id DESC LIMIT 1", (did,)
        )
        if ip:
            extra = (
                f"\n\n🏦 IBAN: <code>{ip['iban']}</code>\n"
                f"Banka: {ip['bank']} | Sahip: {ip['holder']}\n"
                f"Durum: <b>{ip['status']}</b>"
            )
    else:
        ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (did,))
        if ca:
            extra = (
                f"\n\n🔗 Adres: <code>{ca['address']}</code>\n"
                f"Beklenen: {ca['expected']} | Alınan: {ca['received']:.6f}\n"
                f"Durum: <b>{ca['status']}</b>"
            )
    await call.message.edit_text(deal_text(d) + extra)
    await call.answer()


@user_r.callback_query(F.data.startswith("pay_info:"))
async def pay_info(call: CallbackQuery) -> None:
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d:
        await call.answer("Bulunamadı", show_alert=True)
        return
    if d["method"] == "IBAN":
        ii = await cfg_get("iban_info", {})
        await call.message.answer(
            f"🏦 <b>IBAN Ödeme Bilgileri</b>\n\n"
            f"Banka: <b>{ii.get('bank', '—')}</b>\n"
            f"Hesap Sahibi: <b>{ii.get('holder', '—')}</b>\n"
            f"IBAN: <code>{ii.get('iban', 'Henüz ayarlanmadı')}</code>\n\n"
            f"💰 Gönderilecek Tutar: <b>{d['amount']} {d['currency']}</b>\n"
            f"📝 Açıklama: <b>ESCROW-{d['code']}</b>\n\n"
            f"⚠️ Havaleyi yaptıktan sonra admin onaylayacak, bekleyin."
        )
    else:
        ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (did,))
        if ca:
            await call.message.answer(
                f"🔗 <b>{COINS.get(d['method'], d['method'])} Ödeme Adresi</b>\n\n"
                f"<code>{ca['address']}</code>\n\n"
                f"💰 Gönderilecek: <b>{ca['expected']} {d['method']}</b>\n"
                f"⏰ Kalan süre: {PAYMENT_HOURS} saat\n\n"
                f"✅ Ödeme otomatik olarak kontrol edilir, işlem onaylandıktan sonra bildirim alırsınız."
            )
    await call.answer()

# ═══════════════════════════════════════════════════════════════════
#  TESLİM ONAYI
# ═══════════════════════════════════════════════════════════════════

@user_r.callback_query(F.data.startswith("release:"))
async def release_ask(call: CallbackQuery) -> None:
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d or d["buyer_id"] != call.from_user.id:
        await call.answer("❌ Yetkisiz", show_alert=True)
        return
    if d["status"] != "confirmed":
        await call.answer("⚠️ Bu anlaşma henüz onaylanmadı", show_alert=True)
        return
    await call.message.answer(
        f"⚠️ <b>Emin misiniz?</b>\n\n"
        f"<b>{d['amount']} {d['currency']}</b> tutarındaki ödeme satıcıya aktarılacak.\n"
        f"Bu işlem geri alınamaz!",
        reply_markup=ikb(
            [("✅ Evet, Teslim Aldım — Ödemeyi Onayla", f"release_ok:{did}")],
            [("❌ Vazgeç", "close")]
        )
    )
    await call.answer()


@user_r.callback_query(F.data.startswith("release_ok:"))
async def release_ok(call: CallbackQuery, bot: Bot) -> None:
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d or d["buyer_id"] != call.from_user.id:
        await call.answer("❌ Yetkisiz", show_alert=True)
        return
    if d["status"] != "confirmed":
        await call.answer("⚠️ Bu anlaşma zaten işlendi", show_alert=True)
        return

    await exe("UPDATE deals SET status='released' WHERE id=?", (did,))
    fee = round(d["amount"] * FEE_PERCENT / 100, 4)
    net = round(d["amount"] - fee, 4)

    try:
        await call.message.edit_text("✅ Onaylandı! Satıcıya bildirim gönderildi.")
    except Exception:
        await call.message.answer("✅ Onaylandı!")
    await call.answer()

    # Satıcıya: ödeme yöntemi seç
    asyncio.create_task(_start_seller_payout(bot, d, net))

    # Admin'e bildir
    for aid in ADMIN_IDS:
        try:
            await bot.send_message(
                aid,
                f"💸 <b>#{d['code']} Onaylandı — Payout Başladı</b>\n"
                f"Satıcı: <code>{d['seller_id']}</code>\n"
                f"Net: <b>{net} {d['currency']}</b>\n"
                f"⏳ Satıcı ödeme yöntemi seçiyor...",
                reply_markup=ikb(
                    [("💸 Manuel Kripto Gönder", f"adm_payout:{did}")],
                    [("✅ IBAN Gönderildi",       f"adm_iban_done:{did}")]
                )
            )
        except Exception:
            pass


async def _start_seller_payout(bot: Bot, deal: Dict, net: float) -> None:
    """Satıcıya ödeme yöntemi seçtir (IBAN veya Kripto)."""
    coin_label = COINS.get(deal["method"]) if deal["method"] in COINS else None
    btns = [[("🏦 IBAN / EFT ile al", f"seller_pay_method:{deal['id']}:iban")]]
    if coin_label:
        btns.append([(f"🔗 {coin_label} ile al", f"seller_pay_method:{deal['id']}:crypto")])
    await bot.send_message(
        deal["seller_id"],
        f"🎉 <b>Alıcı Teslimi Onayladı!</b>\n\n"
        f"Anlaşma: <b>#{deal['code']}</b>\n"
        f"💰 Size ödenecek net tutar: <b>{net} {deal['currency']}</b>\n\n"
        f"📬 Ödemeyi nasıl almak istersiniz?",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=t, callback_data=cb) for t, cb in row]
            for row in btns
        ])
    )
    await cfg_set(f"payout_pending:{deal['id']}", {
        "seller_id": deal["seller_id"],
        "deal_id":   deal["id"],
        "coin":      deal["method"],
        "amount":    net,
        "currency":  deal["currency"],
        "code":      deal["code"],
    })

# ═══════════════════════════════════════════════════════════════════
#  SATICI ÖDEME YÖNTEMİ SEÇİMİ
# ═══════════════════════════════════════════════════════════════════

@user_r.callback_query(F.data.startswith("seller_pay_method:"))
async def seller_pay_method(call: CallbackQuery) -> None:
    parts   = call.data.split(":")       # ["seller_pay_method", deal_id, method]
    deal_id = int(parts[1])
    method  = parts[2]                   # "iban" veya "crypto"
    uid     = call.from_user.id

    pending = await cfg_get(f"payout_pending:{deal_id}")
    if not pending or pending.get("seller_id") != uid:
        await call.answer("⚠️ Bu işlem size ait değil ya da süresi doldu.", show_alert=True)
        return

    if method == "iban":
        await cfg_set(f"iban_payout:{deal_id}", {
            "seller_id": uid,
            "deal_id":   deal_id,
            "amount":    pending["amount"],
            "currency":  pending["currency"],
            "code":      pending["code"],
            "step":      "iban",
        })
        await cfg_del(f"payout_pending:{deal_id}")
        await call.message.edit_text(
            f"🏦 <b>IBAN ile Ödeme</b>\n\n"
            f"💰 Net tutar: <b>{pending['amount']} {pending['currency']}</b>\n\n"
            f"Lütfen IBAN numaranızı gönderin:\n"
            f"<i>Örnek: TR38 0015 7000 0000 0202 1155 21</i>"
        )

    elif method == "crypto":
        coin = pending.get("coin", "")
        if coin not in COINS:
            await call.answer("⚠️ Bu anlaşma için kripto seçeneği yok.", show_alert=True)
            return
        await cfg_set(f"crypto_payout:{deal_id}", {
            "seller_id": uid,
            "deal_id":   deal_id,
            "coin":      coin,
            "amount":    pending["amount"],
            "code":      pending["code"],
        })
        await cfg_del(f"payout_pending:{deal_id}")
        await call.message.edit_text(
            f"🔗 <b>{COINS.get(coin, coin)} ile Ödeme</b>\n\n"
            f"💰 Net tutar: <b>{pending['amount']} {coin}</b>\n\n"
            f"📬 {coin} cüzdan adresinizi gönderin:"
        )

    await call.answer()

# ═══════════════════════════════════════════════════════════════════
#  DİSPUTE
# ═══════════════════════════════════════════════════════════════════

@user_r.callback_query(F.data.startswith("dispute:"))
async def dispute(call: CallbackQuery, bot: Bot) -> None:
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d:
        return
    if d["status"] in ("released", "cancelled"):
        await call.answer("Bu anlaşma zaten kapatılmış.", show_alert=True)
        return
    await exe("UPDATE deals SET status='disputed' WHERE id=?", (did,))
    for aid in ADMIN_IDS:
        try:
            await bot.send_message(
                aid,
                f"⚠️ <b>Dispute Açıldı!</b>\n\n"
                f"Anlaşma: <b>#{d['code']}</b>\n"
                f"Tutar: {d['amount']} {d['currency']}\n"
                f"Alıcı: <code>{d['buyer_id']}</code>\n"
                f"Satıcı: <code>{d['seller_id']}</code>\n"
                f"Konu: {d['description']}",
                reply_markup=ikb(
                    [("✅ Alıcı Haklı — İptal Et",    f"adm_dis_buyer:{did}")],
                    [("✅ Satıcı Haklı — Ödemeyi Ver", f"adm_dis_seller:{did}")]
                )
            )
        except Exception:
            pass
    await call.message.answer(
        "⚠️ <b>Dispute Açıldı</b>\n\n"
        "Admin en kısa sürede inceleyip karar verecek.\n"
        "Lütfen bekleyin."
    )
    await call.answer()


@user_r.callback_query(F.data == "close")
async def close_cb(call: CallbackQuery) -> None:
    try:
        await call.message.delete()
    except Exception:
        pass
    await call.answer()

# ═══════════════════════════════════════════════════════════════════
#  ANLAŞMA OLUŞTURMA FSM
# ═══════════════════════════════════════════════════════════════════

@user_r.message(F.text == "📋 Anlaşma Oluştur")
async def deal_start(msg: Message, state: FSMContext) -> None:
    u = await one("SELECT is_banned FROM users WHERE user_id=?", (msg.from_user.id,))
    if u and u["is_banned"]:
        await msg.answer("🚫 Hesabınız yasaklandı.")
        return
    await state.clear()
    await state.set_state(Deal.partner)
    await msg.answer(
        "👥 <b>Yeni Anlaşma — Adım 1/6</b>\n\n"
        "Karşı tarafın <b>Telegram ID</b>'sini veya <b>@kullanıcıadı</b>'nı girin:\n"
        "<i>💡 ID öğrenmek için @userinfobot kullanabilirsiniz</i>",
        reply_markup=CANCEL_KB
    )


@user_r.message(StateFilter(Deal.partner))
async def deal_partner(msg: Message, state: FSMContext) -> None:
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal edildi.", reply_markup=main_kb(msg.from_user.id))
        return
    text       = msg.text.strip()
    partner_id = None
    if text.startswith("@"):
        u = await one("SELECT user_id FROM users WHERE username=?", (text[1:],))
        if u:
            partner_id = u["user_id"]
        else:
            await msg.answer(
                "❌ Bu kullanıcı bulunamadı.\n"
                "Karşı tarafın önce bota <b>/start</b> yazması gerekiyor."
            )
            return
    else:
        try:
            partner_id = int(text)
        except ValueError:
            await msg.answer("❌ Geçersiz giriş. Sayısal ID veya @kullanıcıadı girin.")
            return
    if partner_id == msg.from_user.id:
        await msg.answer("❌ Kendinizle anlaşma yapamazsınız!")
        return
    await state.update_data(partner_id=partner_id)
    await state.set_state(Deal.role)
    await msg.answer(
        f"✅ Karşı taraf: <code>{partner_id}</code>\n\n"
        "👤 <b>Adım 2/6 — Bu anlaşmadaki rolünüz nedir?</b>",
        reply_markup=ikb(
            [("🛒 Alıcıyım — Ödemeyi Ben Yapacağım",  "role:buyer")],
            [("🏪 Satıcıyım — Ödemeyi Ben Alacağım",  "role:seller")]
        )
    )


@user_r.callback_query(F.data.startswith("role:"), StateFilter(Deal.role))
async def deal_role(call: CallbackQuery, state: FSMContext) -> None:
    await state.update_data(role=call.data.split(":")[1])
    await state.set_state(Deal.amount)
    await call.message.answer(
        "💰 <b>Adım 3/6 — Anlaşma tutarını girin:</b>\n"
        "<i>Örnek: 500 veya 1250.50</i>",
        reply_markup=CANCEL_KB
    )
    await call.answer()


@user_r.message(StateFilter(Deal.amount))
async def deal_amount(msg: Message, state: FSMContext) -> None:
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id))
        return
    try:
        amount = float(msg.text.replace(",", ".").strip())
        if amount <= 0:
            raise ValueError
    except ValueError:
        await msg.answer("❌ Geçersiz tutar. Pozitif bir sayı girin.\n<i>Örnek: 500</i>")
        return
    await state.update_data(amount=amount)
    await state.set_state(Deal.currency)
    await msg.answer(
        "💱 <b>Adım 4/6 — Para birimini seçin:</b>",
        reply_markup=ikb(
            [("🇹🇷 TRY — Türk Lirası", "cur:TRY"), ("💵 USD — Dolar", "cur:USD")],
            [("💶 EUR — Euro",         "cur:EUR"), ("💲 USDT",         "cur:USDT")]
        )
    )


@user_r.callback_query(F.data.startswith("cur:"), StateFilter(Deal.currency))
async def deal_currency(call: CallbackQuery, state: FSMContext) -> None:
    await state.update_data(currency=call.data.split(":")[1])
    await state.set_state(Deal.desc)
    await call.message.answer(
        "📝 <b>Adım 5/6 — Anlaşma konusunu açıklayın:</b>\n"
        "<i>Örnek: Logo tasarımı — 3 konsept, 2 revizyon hakkı</i>",
        reply_markup=CANCEL_KB
    )
    await call.answer()


@user_r.message(StateFilter(Deal.desc))
async def deal_desc(msg: Message, state: FSMContext) -> None:
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id))
        return
    if len(msg.text.strip()) < 5:
        await msg.answer("❌ Açıklama çok kısa. En az 5 karakter girin.")
        return
    await state.update_data(description=msg.text.strip())
    await state.set_state(Deal.method)
    await msg.answer(
        "💳 <b>Adım 6/6 — Ödeme yöntemini seçin:</b>",
        reply_markup=ikb(
            [("🏦 IBAN / Havale / EFT",   "mth:IBAN")],
            [("💎 USDT TRC20",             "mth:USDT_TRC20"), ("⚡ TRX", "mth:TRX")],
            [("🔷 ETH",                    "mth:ETH"),         ("₿ BTC", "mth:BTC")]
        )
    )


@user_r.callback_query(F.data.startswith("mth:"), StateFilter(Deal.method))
async def deal_method(call: CallbackQuery, state: FSMContext) -> None:
    method = call.data.split(":")[1]
    await state.update_data(method=method)
    await state.set_state(Deal.confirm)
    data   = await state.get_data()
    fee    = round(data["amount"] * FEE_PERCENT / 100, 4)
    mlabel = "IBAN Havale / EFT" if method == "IBAN" else COINS.get(method, method)
    await call.message.answer(
        f"📋 <b>Anlaşma Özeti — Onay</b>\n\n"
        f"👤 Karşı taraf: <code>{data['partner_id']}</code>\n"
        f"👔 Rolünüz: <b>{'Alıcı' if data['role'] == 'buyer' else 'Satıcı'}</b>\n"
        f"💰 Tutar: <b>{data['amount']} {data['currency']}</b>\n"
        f"💸 Komisyon (%{FEE_PERCENT}): <b>{fee} {data['currency']}</b>\n"
        f"💵 Net (satıcıya): <b>{round(data['amount'] - fee, 4)} {data['currency']}</b>\n"
        f"📦 Konu: {data['description']}\n"
        f"💳 Ödeme: <b>{mlabel}</b>\n\n"
        f"Onaylıyor musunuz?",
        reply_markup=ikb(
            [("✅ Evet, Onayla", "dcreate:yes")],
            [("❌ İptal",        "dcreate:no")]
        )
    )
    await call.answer()


@user_r.callback_query(F.data.startswith("dcreate:"), StateFilter(Deal.confirm))
async def deal_confirm(call: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    if call.data == "dcreate:no":
        await state.clear()
        await call.message.answer("❌ İptal edildi.", reply_markup=main_kb(call.from_user.id))
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
        """INSERT INTO deals
           (code, buyer_id, seller_id, creator_id, amount, currency,
            description, method, status, deadline)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (code, buyer_id, seller_id, uid,
         data["amount"], data["currency"],
         data["description"], method, "payment_pending", deadline)
    )

    # Ödeme kaydı oluştur
    if method == "IBAN":
        ii = await cfg_get("iban_info", {})
        await exe(
            "INSERT INTO iban_pay(deal_id,iban,bank,holder,amount,currency) VALUES(?,?,?,?,?,?)",
            (deal_id, ii.get("iban", "—"), ii.get("bank", "—"), ii.get("holder", "—"),
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
            f"Kod: <b>#{code}</b>\n"
            f"Rolünüz: <b>{partner_role}</b>\n"
            f"Tutar: <b>{data['amount']} {data['currency']}</b>\n"
            f"Konu: {data['description']}\n\n"
            f"Anlaşmayı görüntülemek için aşağıdaki butona tıklayın:",
            reply_markup=ikb([("📋 Anlaşmayı Görüntüle", f"detail:{deal_id}")])
        )
    except Exception:
        pass

    # Ödeme bilgisini oluştur
    if method == "IBAN":
        ii  = await cfg_get("iban_info", {})
        txt = (
            f"✅ <b>Anlaşma #{code} Oluşturuldu!</b>\n\n"
            f"🏦 Banka: <b>{ii.get('bank', '—')}</b>\n"
            f"👤 Hesap Sahibi: <b>{ii.get('holder', '—')}</b>\n"
            f"💳 IBAN: <code>{ii.get('iban', 'Henüz ayarlanmadı')}</code>\n\n"
            f"💰 Gönderilecek Tutar: <b>{data['amount']} {data['currency']}</b>\n"
            f"📝 Açıklama: <b>ESCROW-{code}</b>\n\n"
            f"⚠️ Havaleyi yaptıktan sonra admin onaylayacak."
        )
    else:
        ca  = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (deal_id,))
        txt = (
            f"✅ <b>Anlaşma #{code} Oluşturuldu!</b>\n\n"
            f"🔗 {COINS.get(method, method)} Ödeme Adresi:\n"
            f"<code>{ca['address']}</code>\n\n"
            f"💰 Gönderilecek: <b>{data['amount']} {method}</b>\n"
            f"⏰ Ödeme süresi: {PAYMENT_HOURS} saat\n\n"
            f"✅ Ödeme otomatik kontrol edilir."
        )
    await call.message.answer(txt, reply_markup=main_kb(uid))
    await call.answer()

# ═══════════════════════════════════════════════════════════════════
#  SATICI — IBAN PAYOUT CATCHER  (state=None iken)
# ═══════════════════════════════════════════════════════════════════

@user_r.message(StateFilter(None), F.text)
async def catch_seller_iban(msg: Message, bot: Bot) -> None:
    uid  = msg.from_user.id
    text = msg.text.strip()

    rows = await many("SELECT key, value FROM settings WHERE key LIKE 'iban_payout:%'")
    for row in rows:
        try:
            data = json.loads(row["value"])
        except Exception:
            continue
        if data.get("seller_id") != uid:
            continue

        step = data.get("step", "iban")

        if step == "iban":
            iban = text.replace(" ", "").upper()
            if len(iban) < 16:
                await msg.answer(
                    "❌ Geçersiz IBAN. Tekrar girin:\n"
                    "<i>Örnek: TR38 0015 7000 0000 0202 1155 21</i>"
                )
                return
            data["iban"] = iban
            data["step"] = "bank"
            await cfg_set(row["key"], data)
            await msg.answer("🏦 Bankanızın adını girin:\n<i>Örnek: Ziraat Bankası</i>")
            return

        elif step == "bank":
            if len(text) < 2:
                await msg.answer("❌ Geçersiz banka adı. Tekrar girin:")
                return
            data["bank"] = text
            data["step"] = "holder"
            await cfg_set(row["key"], data)
            await msg.answer("👤 Hesap sahibinin tam adını girin:\n<i>Örnek: Ahmet Yılmaz</i>")
            return

        elif step == "holder":
            if len(text) < 3:
                await msg.answer("❌ Geçersiz isim. Tekrar girin:")
                return
            data["holder"] = text
            await msg.answer(
                f"✅ <b>Banka bilgileriniz alındı!</b>\n\n"
                f"🏦 IBAN: <code>{data['iban']}</code>\n"
                f"🏛 Banka: {data['bank']}\n"
                f"👤 Hesap Sahibi: {data['holder']}\n\n"
                f"💰 Transfer tutarı: <b>{data['amount']} {data['currency']}</b>\n\n"
                f"⏳ Admin en kısa sürede ödemenizi gerçekleştirecek."
            )
            for aid in ADMIN_IDS:
                try:
                    await bot.send_message(
                        aid,
                        f"🏦 <b>Satıcı IBAN Bilgisi Geldi!</b>\n\n"
                        f"Anlaşma: <b>#{data['code']}</b>\n"
                        f"Satıcı: <code>{uid}</code>\n\n"
                        f"💳 IBAN: <code>{data['iban']}</code>\n"
                        f"🏛 Banka: {data['bank']}\n"
                        f"👤 Hesap Sahibi: {data['holder']}\n\n"
                        f"💰 Gönderilecek: <b>{data['amount']} {data['currency']}</b>",
                        reply_markup=ikb(
                            [("✅ Ödemeyi Yaptım — Satıcıya Bildir",
                              f"adm_iban_done:{data['deal_id']}")]
                        )
                    )
                except Exception:
                    pass
            await cfg_del(row["key"])
            return

# ═══════════════════════════════════════════════════════════════════
#  SATICI — KRİPTO PAYOUT CATCHER  (state=None iken)
# ═══════════════════════════════════════════════════════════════════

@user_r.message(StateFilter(None), F.text)
async def catch_crypto_payout(msg: Message, bot: Bot) -> None:
    uid  = msg.from_user.id
    rows = await many("SELECT key, value FROM settings WHERE key LIKE 'crypto_payout:%'")
    for row in rows:
        try:
            data = json.loads(row["value"])
        except Exception:
            continue
        if data.get("seller_id") != uid:
            continue

        addr = msg.text.strip()
        coin = data["coin"]
        valid = (
            (coin in ("TRX", "USDT_TRC20") and addr.startswith("T") and len(addr) == 34) or
            (coin == "ETH"                  and addr.startswith("0x") and len(addr) == 42) or
            (coin == "BTC"                  and (addr.startswith("1") or
                                                 addr.startswith("3") or
                                                 addr.startswith("bc1")))
        )
        if not valid:
            await msg.answer(
                f"❌ Geçersiz <b>{coin}</b> adresi.\n"
                f"Lütfen geçerli bir {coin} cüzdan adresi gönderin:"
            )
            return

        ca = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (data["deal_id"],))
        if not ca:
            await msg.answer("❌ Kripto adres kaydı bulunamadı. Adminle iletişime geçin.")
            return

        await msg.answer(f"⏳ <b>{data['amount']} {coin}</b> gönderiliyor, lütfen bekleyin...")
        tx = None
        if coin in ("TRX", "USDT_TRC20"):
            tx = await send_tron(ca["address"], ca["privkey"], addr, data["amount"], coin)
        elif coin == "ETH":
            tx = await send_eth(ca["privkey"], addr, data["amount"])

        if tx:
            await msg.answer(
                f"🎉 <b>Ödeme Gönderildi!</b>\n\n"
                f"💰 Tutar: <b>{data['amount']} {coin}</b>\n"
                f"📬 Adres: <code>{addr}</code>\n"
                f"🔗 TX Hash: <code>{tx}</code>\n\n"
                f"✅ İşlem blockchain'e yayınlandı."
            )
            await exe(
                "INSERT INTO txlog(deal_id,type,amount,currency,to_address,tx_hash) VALUES(?,?,?,?,?,?)",
                (data["deal_id"], "payout", data["amount"], coin, addr, tx)
            )
            # Alıcıya onay bildirimi
            d = await one("SELECT * FROM deals WHERE id=?", (data["deal_id"],))
            if d:
                try:
                    await bot.send_message(
                        d["buyer_id"],
                        f"✅ <b>Anlaşma Tamamlandı!</b>\n\n"
                        f"Anlaşma: <b>#{data['code']}</b>\n"
                        f"Satıcıya ödeme yapıldı. Anlaşma başarıyla kapatıldı."
                    )
                except Exception:
                    pass
        else:
            await msg.answer(
                "⚠️ Otomatik gönderim şu an başarısız oldu.\n"
                "Admin en kısa sürede manuel olarak gönderecek."
            )
            for aid in ADMIN_IDS:
                try:
                    await bot.send_message(
                        aid,
                        f"🚨 <b>Kripto Gönderim BAŞARISIZ!</b>\n\n"
                        f"Anlaşma: #{data['code']}\n"
                        f"Satıcı: <code>{uid}</code>\n"
                        f"Coin: {coin} | Tutar: {data['amount']}\n"
                        f"Hedef: <code>{addr}</code>",
                        reply_markup=ikb([("💸 Manuel Gönder", f"adm_payout:{data['deal_id']}")])
                    )
                except Exception:
                    pass

        await cfg_del(row["key"])
        return

# ═══════════════════════════════════════════════════════════════════
#  ADMİN PANEL
# ═══════════════════════════════════════════════════════════════════

def admin_panel_kb() -> InlineKeyboardMarkup:
    return ikb(
        [("🏦 IBAN Ayarla",      "adm:iban"),   ("📋 Bekleyen IBAN",    "adm:pending_iban")],
        [("💎 Kripto Bakiyeler", "adm:balances"), ("💸 Fon Gönder",      "adm:send")],
        [("📊 Anlaşmalar",      "adm:deals"),   ("⚠️ Disputelar",      "adm:disputes")],
        [("👥 Kullanıcılar",    "adm:users"),   ("📢 Duyuru",           "adm:broadcast")],
        [("📈 İstatistikler",   "adm:stats")]
    )


@admin_r.message(Command("admin"))
async def admin_cmd(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id):
        await msg.answer("🚫 Yetkisiz erişim!")
        return
    await state.clear()
    await msg.answer("👑 <b>Admin Paneli</b>", reply_markup=admin_panel_kb())


@admin_r.message(F.text == "👑 Admin Panel")
async def admin_btn(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id):
        await msg.answer("🚫 Yetkisiz erişim!")
        return
    await state.clear()
    await msg.answer("👑 <b>Admin Paneli</b>", reply_markup=admin_panel_kb())


@admin_r.callback_query(F.data.startswith("adm:"))
async def admin_cb(call: CallbackQuery, state: FSMContext, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫 Yetkisiz!", show_alert=True)
        return
    action = call.data.split(":")[1]

    # ── IBAN AYARLA ──────────────────────────────────────────────────
    if action == "iban":
        ii  = await cfg_get("iban_info", {})
        cur = ""
        if ii:
            cur = (
                f"\n\n<b>Mevcut:</b>\n"
                f"IBAN: <code>{ii.get('iban', '—')}</code>\n"
                f"Banka: {ii.get('bank', '—')} | Sahip: {ii.get('holder', '—')}"
            )
        await state.set_state(Adm.iban_val)
        await call.message.answer(
            f"🏦 <b>IBAN Güncelle</b>{cur}\n\n"
            f"Yeni IBAN numarasını girin (TR ile başlayan 26 karakter):",
            reply_markup=CANCEL_KB
        )

    # ── BEKLEYEN IBAN ────────────────────────────────────────────────
    elif action == "pending_iban":
        pays = await many("""
            SELECT ip.*, d.code, d.buyer_id, d.description
            FROM iban_pay ip
            JOIN deals d ON ip.deal_id = d.id
            WHERE ip.status = 'waiting'
            ORDER BY ip.created_at DESC
        """)
        if not pays:
            await call.message.answer("✅ Bekleyen IBAN ödemesi yok.")
        for p in pays:
            await call.message.answer(
                f"🏦 <b>IBAN Ödeme Onayı</b>\n\n"
                f"Anlaşma: <b>#{p['code']}</b>\n"
                f"Alıcı: <code>{p['buyer_id']}</code>\n"
                f"Konu: {p['description']}\n"
                f"Tutar: <b>{p['amount']} {p['currency']}</b>",
                reply_markup=ikb(
                    [("✅ Ödeme Yapıldı — Onayla", f"adm_iban_ok:{p['deal_id']}")],
                    [("❌ Reddet — İptal Et",       f"adm_iban_no:{p['deal_id']}")]
                )
            )

    # ── KRİPTO BAKİYELER ─────────────────────────────────────────────
    elif action == "balances":
        await call.message.answer("⏳ Bakiyeler sorgulanıyor...")
        addrs = await many("""
            SELECT ca.*, d.code
            FROM crypto_addr ca
            JOIN deals d ON ca.deal_id = d.id
            WHERE d.status NOT IN ('cancelled', 'released')
            ORDER BY ca.created_at DESC
            LIMIT 20
        """)
        if not addrs:
            await call.message.answer("💤 Aktif kripto adresi yok.")
        else:
            txt  = "💎 <b>Aktif Kripto Bakiyeleri</b>\n\n"
            btns = []
            for a in addrs:
                bal  = await get_balance(a["coin"], a["address"])
                txt += (
                    f"#{a['code']} | {a['coin']}\n"
                    f"<code>{a['address'][:30]}...</code>\n"
                    f"Beklenen: {a['expected']} | Gerçek: {bal:.6f}\n"
                    f"Durum: {a['status']}\n"
                    f"────────────\n"
                )
                if bal > 0:
                    btns.append([(f"💸 #{a['code']} Gönder", f"adm_bal_send:{a['id']}")])
            await call.message.answer(txt, reply_markup=ikb(*btns) if btns else None)

    # ── FON GÖNDER ───────────────────────────────────────────────────
    elif action == "send":
        addrs = await many("""
            SELECT ca.*, d.code
            FROM crypto_addr ca
            JOIN deals d ON ca.deal_id = d.id
            WHERE ca.received > 0 OR ca.status = 'received'
        """)
        if not addrs:
            await call.message.answer("💤 Bakiyeli adres bulunamadı.")
        else:
            btns = [
                [(f"#{a['code']} — {a['coin']} ({a['received']})", f"adm_bal_send:{a['id']}")]
                for a in addrs
            ]
            await call.message.answer("💸 <b>Hangi adresten gönderim yapılsın?</b>", reply_markup=ikb(*btns))

    # ── ANLAŞMALAR ───────────────────────────────────────────────────
    elif action == "deals":
        await call.message.answer(
            "📊 <b>Anlaşma Filtresi:</b>",
            reply_markup=ikb(
                [("⏳ Ödeme Bekleyen", "adm_dl:payment_pending"), ("🔐 Onaylanan", "adm_dl:confirmed")],
                [("💸 Tamamlanan",    "adm_dl:released"),          ("❌ İptal",    "adm_dl:cancelled")],
                [("⚠️ Dispute",       "adm_dl:disputed"),          ("📋 Tümü",    "adm_dl:all")]
            )
        )

    # ── DISPUTELAR ────────────────────────────────────────────────────
    elif action == "disputes":
        deals = await many(
            "SELECT * FROM deals WHERE status='disputed' ORDER BY created_at DESC"
        )
        if not deals:
            await call.message.answer("✅ Açık dispute yok.")
        for d in deals:
            await call.message.answer(
                deal_text(d),
                reply_markup=ikb(
                    [("✅ Alıcı Haklı — İptal Et",    f"adm_dis_buyer:{d['id']}")],
                    [("✅ Satıcı Haklı — Ödemeyi Ver", f"adm_dis_seller:{d['id']}")]
                )
            )

    # ── İSTATİSTİKLER ────────────────────────────────────────────────
    elif action == "stats":
        total    = await one("SELECT COUNT(*) c FROM deals")
        released = await one("SELECT COUNT(*) c FROM deals WHERE status='released'")
        disputed = await one("SELECT COUNT(*) c FROM deals WHERE status='disputed'")
        pending  = await one("SELECT COUNT(*) c FROM deals WHERE status='payment_pending'")
        vol      = await one("SELECT COALESCE(SUM(amount),0) s FROM deals WHERE status='released'")
        users    = await one("SELECT COUNT(*) c FROM users")
        banned   = await one("SELECT COUNT(*) c FROM users WHERE is_banned=1")
        fee_earn = round((vol["s"] or 0) * FEE_PERCENT / 100, 2)
        await call.message.answer(
            f"📈 <b>Bot İstatistikleri</b>\n\n"
            f"👥 Toplam Kullanıcı: <b>{users['c']}</b>\n"
            f"🚫 Yasaklı: <b>{banned['c']}</b>\n\n"
            f"📋 Toplam Anlaşma: <b>{total['c']}</b>\n"
            f"⏳ Ödeme Bekleyen: <b>{pending['c']}</b>\n"
            f"✅ Tamamlanan: <b>{released['c']}</b>\n"
            f"⚠️ Açık Dispute: <b>{disputed['c']}</b>\n\n"
            f"💰 Toplam Hacim: <b>{vol['s']:.2f}</b>\n"
            f"💸 Tahmini Kazanç (%{FEE_PERCENT}): <b>{fee_earn}</b>"
        )

    # ── DUYURU ──────────────────────────────────────────────────────
    elif action == "broadcast":
        await state.set_state(Adm.broadcast)
        await call.message.answer(
            "📢 Tüm kullanıcılara gönderilecek mesajı yazın:",
            reply_markup=CANCEL_KB
        )

    # ── KULLANICILAR ─────────────────────────────────────────────────
    elif action == "users":
        users = await many(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT 20"
        )
        txt  = "👥 <b>Son 20 Kullanıcı</b>\n\n"
        btns = []
        for u in users:
            st   = "🚫" if u["is_banned"] else "✅"
            name = u["full_name"] or "İsimsiz"
            txt += f"{st} {name} | <code>{u['user_id']}</code>\n"
            if u["is_banned"]:
                btns.append([(f"🔓 {u['user_id']} — Yasağı Kaldır", f"adm_unban:{u['user_id']}")])
            else:
                btns.append([(f"🚫 {u['user_id']} — Yasakla", f"adm_ban:{u['user_id']}")])
        await call.message.answer(txt, reply_markup=ikb(*btns) if btns else None)

    await call.answer()

# ─── IBAN FSM (Admin) ────────────────────────────────────────────

@admin_r.message(StateFilter(Adm.iban_val))
async def adm_iban_val(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id):
        return
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id))
        return
    iban = msg.text.strip().replace(" ", "").upper()
    if not (iban.startswith("TR") and len(iban) == 26):
        await msg.answer("❌ Geçersiz IBAN! TR ile başlayan 26 karakterli numara girin:")
        return
    await state.update_data(iban=iban)
    await state.set_state(Adm.iban_bank)
    await msg.answer("🏦 Banka adını girin:\n<i>Örnek: Ziraat Bankası</i>")


@admin_r.message(StateFilter(Adm.iban_bank))
async def adm_iban_bank(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id):
        return
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id))
        return
    await state.update_data(bank=msg.text.strip())
    await state.set_state(Adm.iban_holder)
    await msg.answer("👤 Hesap sahibinin tam adını girin:")


@admin_r.message(StateFilter(Adm.iban_holder))
async def adm_iban_holder(msg: Message, state: FSMContext) -> None:
    if not is_admin(msg.from_user.id):
        return
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id))
        return
    data = await state.get_data()
    await state.clear()
    ii   = {"iban": data["iban"], "bank": data["bank"], "holder": msg.text.strip()}
    await cfg_set("iban_info", ii)
    await msg.answer(
        f"✅ <b>IBAN Başarıyla Kaydedildi!</b>\n\n"
        f"IBAN: <code>{ii['iban']}</code>\n"
        f"Banka: {ii['bank']}\n"
        f"Hesap Sahibi: {ii['holder']}",
        reply_markup=main_kb(msg.from_user.id)
    )

# ─── IBAN Alıcı Ödemesi Onay / Red ──────────────────────────────

@admin_r.callback_query(F.data.startswith("adm_iban_ok:"))
async def adm_iban_ok(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    did = int(call.data.split(":")[1])
    await exe(
        "UPDATE iban_pay SET status='confirmed', admin_id=?, confirmed_at=? WHERE deal_id=?",
        (call.from_user.id, datetime.now().isoformat(), did)
    )
    await exe("UPDATE deals SET status='confirmed' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    # Alıcıya: ödemen onaylandı + teslim al butonları
    try:
        await bot.send_message(
            d["buyer_id"],
            f"✅ <b>Ödemeniz Onaylandı!</b>\n\n"
            f"Anlaşma: <b>#{d['code']}</b>\n"
            f"💰 Tutar: <b>{d['amount']} {d['currency']}</b>\n\n"
            f"📦 Ürün veya hizmeti teslim aldığınızda butona basın.\n"
            f"Sorun varsa dispute açabilirsiniz:",
            reply_markup=ikb(
                [("✅ Teslim Aldım — Ödemeyi Onayla", f"release:{did}")],
                [("⚠️ Sorun Var — Dispute Aç",         f"dispute:{did}")]
            )
        )
    except Exception:
        pass
    # Satıcıya: ödeme alındı, teslim et
    try:
        await bot.send_message(
            d["seller_id"],
            f"🔔 <b>Alıcı Ödemesi Doğrulandı!</b>\n\n"
            f"Anlaşma: <b>#{d['code']}</b>\n\n"
            f"✅ Alıcının ödemesi admin tarafından onaylandı.\n"
            f"⏳ Ürün/hizmeti teslim edin — alıcı onayladıktan sonra ödemeniz yapılacak."
        )
    except Exception:
        pass
    try:
        await call.message.edit_text("✅ Ödeme onaylandı! Taraflara bildirim gönderildi.")
    except Exception:
        await call.message.answer("✅ Onaylandı!")
    await call.answer()


@admin_r.callback_query(F.data.startswith("adm_iban_no:"))
async def adm_iban_no(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    did = int(call.data.split(":")[1])
    await exe("UPDATE iban_pay SET status='rejected' WHERE deal_id=?", (did,))
    await exe("UPDATE deals SET status='cancelled' WHERE id=?", (did,))
    d = await one("SELECT * FROM deals WHERE id=?", (did,))
    for uid in [d["buyer_id"], d["seller_id"]]:
        try:
            await bot.send_message(
                uid,
                f"❌ <b>Anlaşma İptal Edildi</b>\n\n"
                f"Anlaşma: <b>#{d['code']}</b>\n"
                f"IBAN ödemesi reddedildi ve anlaşma iptal edildi."
            )
        except Exception:
            pass
    try:
        await call.message.edit_text("❌ Reddedildi. Anlaşma iptal edildi.")
    except Exception:
        pass
    await call.answer()

# ─── Admin: Satıcıya IBAN Havale Yaptım ─────────────────────────

@admin_r.callback_query(F.data.startswith("adm_iban_done:"))
async def adm_iban_done(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if d:
        fee = round(d["amount"] * FEE_PERCENT / 100, 4)
        net = round(d["amount"] - fee, 4)
        # Satıcıya: para gönderildi
        try:
            await bot.send_message(
                d["seller_id"],
                f"🎉 <b>Ödemeniz Yapıldı!</b>\n\n"
                f"Anlaşma: <b>#{d['code']}</b>\n"
                f"💰 Net tutar: <b>{net} {d['currency']}</b>\n\n"
                f"✅ Para hesabınıza aktarılmıştır. İyi günler dileriz!"
            )
        except Exception:
            pass
        # Alıcıya: anlaşma tamamlandı bildirimi
        try:
            await bot.send_message(
                d["buyer_id"],
                f"✅ <b>Anlaşma Tamamlandı!</b>\n\n"
                f"Anlaşma: <b>#{d['code']}</b>\n"
                f"Satıcıya ödeme yapıldı. Teşekkürler!"
            )
        except Exception:
            pass
    try:
        await call.message.edit_text(
            "✅ IBAN havalesi gönderildi olarak işaretlendi. Satıcıya bildirim yapıldı."
        )
    except Exception:
        pass
    await call.answer()

# ─── Anlaşma Listesi ─────────────────────────────────────────────

@admin_r.callback_query(F.data.startswith("adm_dl:"))
async def adm_deal_list(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    status = call.data.split(":")[1]
    if status == "all":
        deals = await many("SELECT * FROM deals ORDER BY created_at DESC LIMIT 15")
    else:
        deals = await many(
            "SELECT * FROM deals WHERE status=? ORDER BY created_at DESC LIMIT 15",
            (status,)
        )
    if not deals:
        await call.message.answer("📭 Bu durumda anlaşma yok.")
    for d in deals:
        await call.message.answer(
            deal_text(d),
            reply_markup=ikb([("🔧 Yönet", f"adm_mgmt:{d['id']}")])
        )
    await call.answer()


@admin_r.callback_query(F.data.startswith("adm_mgmt:"))
async def adm_mgmt(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    if not d:
        await call.answer("Bulunamadı", show_alert=True)
        return
    btns = []
    if d["status"] not in ("released", "cancelled"):
        btns.append([("❌ Anlaşmayı İptal Et", f"adm_cancel:{did}")])
    if d["status"] in ("confirmed", "payment_pending"):
        btns.append([("💸 Zorla Serbest Bırak", f"adm_force_release:{did}")])
    await call.message.answer(deal_text(d), reply_markup=ikb(*btns) if btns else None)
    await call.answer()


@admin_r.callback_query(F.data.startswith("adm_cancel:"))
async def adm_cancel(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    did = int(call.data.split(":")[1])
    await exe("UPDATE deals SET status='cancelled' WHERE id=?", (did,))
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    for uid in [d["buyer_id"], d["seller_id"]]:
        try:
            await bot.send_message(
                uid,
                f"❌ <b>Anlaşma İptal Edildi</b>\n\n"
                f"Anlaşma: <b>#{d['code']}</b>\nAdmin tarafından iptal edildi."
            )
        except Exception:
            pass
    try:
        await call.message.edit_text("❌ Anlaşma iptal edildi.")
    except Exception:
        pass
    await call.answer()


@admin_r.callback_query(F.data.startswith("adm_force_release:"))
async def adm_force_release(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    await exe("UPDATE deals SET status='released' WHERE id=?", (did,))
    fee = round(d["amount"] * FEE_PERCENT / 100, 4)
    net = round(d["amount"] - fee, 4)
    for uid in [d["buyer_id"], d["seller_id"]]:
        try:
            await bot.send_message(
                uid,
                f"💸 <b>Anlaşma Serbest Bırakıldı</b>\n\n"
                f"Anlaşma: <b>#{d['code']}</b>\nAdmin tarafından ödeme serbest bırakıldı."
            )
        except Exception:
            pass
    asyncio.create_task(_start_seller_payout(bot, d, net))
    try:
        await call.message.edit_text("✅ Serbest bırakıldı. Satıcıya ödeme seçeneği gönderildi.")
    except Exception:
        pass
    await call.answer()

# ─── Dispute Çözüm ───────────────────────────────────────────────

@admin_r.callback_query(F.data.startswith("adm_dis_buyer:"))
async def adm_dis_buyer(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    did = int(call.data.split(":")[1])
    await exe("UPDATE deals SET status='cancelled' WHERE id=?", (did,))
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    try:
        await bot.send_message(
            d["buyer_id"],
            f"✅ <b>Dispute Sonucu: Alıcı Haklı</b>\n\n"
            f"Anlaşma: <b>#{d['code']}</b>\nAnlaşma iptal edildi."
        )
    except Exception:
        pass
    try:
        await bot.send_message(
            d["seller_id"],
            f"⚠️ <b>Dispute Sonucu: Alıcı Haklı Bulundu</b>\n\n"
            f"Anlaşma: <b>#{d['code']}</b>\nAnlaşma iptal edildi."
        )
    except Exception:
        pass
    try:
        await call.message.edit_text("✅ Alıcı lehine çözüldü.")
    except Exception:
        pass
    await call.answer()


@admin_r.callback_query(F.data.startswith("adm_dis_seller:"))
async def adm_dis_seller(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    did = int(call.data.split(":")[1])
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    await exe("UPDATE deals SET status='released' WHERE id=?", (did,))
    fee = round(d["amount"] * FEE_PERCENT / 100, 4)
    net = round(d["amount"] - fee, 4)
    try:
        await bot.send_message(
            d["seller_id"],
            f"✅ <b>Dispute Sonucu: Satıcı Haklı</b>\n\n"
            f"Anlaşma: <b>#{d['code']}</b>\nÖdemeniz yapılacak."
        )
    except Exception:
        pass
    try:
        await bot.send_message(
            d["buyer_id"],
            f"⚠️ <b>Dispute Sonucu: Satıcı Haklı Bulundu</b>\n\n"
            f"Anlaşma: <b>#{d['code']}</b>"
        )
    except Exception:
        pass
    asyncio.create_task(_start_seller_payout(bot, d, net))
    try:
        await call.message.edit_text("✅ Satıcı lehine çözüldü. Payout başlatıldı.")
    except Exception:
        pass
    await call.answer()

# ─── Admin: Kripto Gönder ────────────────────────────────────────

@admin_r.callback_query(F.data.startswith("adm_bal_send:"))
async def adm_bal_send(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    aid = int(call.data.split(":")[1])
    ca  = await one("SELECT * FROM crypto_addr WHERE id=?", (aid,))
    if not ca:
        await call.answer("Bulunamadı", show_alert=True)
        return
    await state.update_data(
        ca_id=aid, ca_coin=ca["coin"],
        ca_addr=ca["address"], ca_priv=ca["privkey"]
    )
    await state.set_state(Adm.send_to)
    await call.message.answer(
        f"💸 <b>Kripto Gönder</b>\n\n"
        f"Coin: <b>{ca['coin']}</b>\n"
        f"Kaynak: <code>{ca['address']}</code>\n\n"
        f"Hedef cüzdan adresini girin:",
        reply_markup=CANCEL_KB
    )
    await call.answer()


@admin_r.callback_query(F.data.startswith("adm_payout:"))
async def adm_payout(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    did = int(call.data.split(":")[1])
    ca  = await one("SELECT * FROM crypto_addr WHERE deal_id=?", (did,))
    if not ca:
        await call.answer("Kripto adresi bulunamadı", show_alert=True)
        return
    d   = await one("SELECT * FROM deals WHERE id=?", (did,))
    net = round(d["amount"] - d["amount"] * FEE_PERCENT / 100, 6)
    await state.update_data(
        ca_id=ca["id"], ca_coin=ca["coin"],
        ca_addr=ca["address"], ca_priv=ca["privkey"],
        forced_amount=net, deal_id=did
    )
    await state.set_state(Adm.send_to)
    await call.message.answer(
        f"💸 Satıcıya Kripto Gönder\n"
        f"Net tutar: <b>{net} {ca['coin']}</b>\n\n"
        f"Satıcının cüzdan adresini girin:",
        reply_markup=CANCEL_KB
    )
    await call.answer()


@admin_r.message(StateFilter(Adm.send_to))
async def adm_send_to(msg: Message, state: FSMContext, bot: Bot) -> None:
    if not is_admin(msg.from_user.id):
        return
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id))
        return
    await state.update_data(send_to=msg.text.strip())
    data = await state.get_data()
    if "forced_amount" in data:
        await adm_do_send(msg, state, bot)
    else:
        await state.set_state(Adm.send_amt)
        await msg.answer("💰 Gönderilecek miktarı girin:")


@admin_r.message(StateFilter(Adm.send_amt))
async def adm_send_amt(msg: Message, state: FSMContext, bot: Bot) -> None:
    if not is_admin(msg.from_user.id):
        return
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id))
        return
    try:
        amount = float(msg.text.replace(",", ".").strip())
    except ValueError:
        await msg.answer("❌ Geçersiz miktar.")
        return
    await state.update_data(send_amount=amount)
    await adm_do_send(msg, state, bot)


async def adm_do_send(msg: Message, state: FSMContext, bot: Bot) -> None:
    data   = await state.get_data()
    amount = data.get("send_amount") or data.get("forced_amount")
    if not amount:
        return
    await state.clear()
    await msg.answer(f"⏳ {amount} {data['ca_coin']} gönderiliyor...")
    tx = None
    if data["ca_coin"] in ("TRX", "USDT_TRC20"):
        tx = await send_tron(data["ca_addr"], data["ca_priv"], data["send_to"], amount, data["ca_coin"])
    elif data["ca_coin"] == "ETH":
        tx = await send_eth(data["ca_priv"], data["send_to"], amount)

    if tx:
        await msg.answer(
            f"✅ <b>Gönderim Başarılı!</b>\n\n"
            f"TX: <code>{tx}</code>\n"
            f"Tutar: {amount} {data['ca_coin']}\n"
            f"Hedef: <code>{data['send_to']}</code>",
            reply_markup=main_kb(msg.from_user.id)
        )
        await exe(
            "INSERT INTO txlog(type,amount,currency,from_address,to_address,tx_hash,note) VALUES(?,?,?,?,?,?,?)",
            ("admin_send", amount, data["ca_coin"], data["ca_addr"], data["send_to"], tx, "Admin")
        )
        # Satıcıya bildirim
        deal_id = data.get("deal_id")
        if deal_id:
            d = await one("SELECT * FROM deals WHERE id=?", (deal_id,))
            if d:
                try:
                    await bot.send_message(
                        d["seller_id"],
                        f"🎉 <b>Ödemeniz Gönderildi!</b>\n\n"
                        f"Anlaşma: <b>#{d['code']}</b>\n"
                        f"💰 Tutar: <b>{amount} {data['ca_coin']}</b>\n"
                        f"📬 Adres: <code>{data['send_to']}</code>\n"
                        f"🔗 TX: <code>{tx}</code>\n\n"
                        f"✅ İşlem tamamlandı!"
                    )
                except Exception:
                    pass
                try:
                    await bot.send_message(
                        d["buyer_id"],
                        f"✅ <b>Anlaşma Tamamlandı!</b>\n\n"
                        f"Anlaşma: <b>#{d['code']}</b>\n"
                        f"Satıcıya ödeme yapıldı. Teşekkürler!"
                    )
                except Exception:
                    pass
    else:
        await msg.answer(
            "❌ Gönderim başarısız!\n"
            "Kütüphane kurulu mu? Bakiye yeterli mi? Kontrol edin.",
            reply_markup=main_kb(msg.from_user.id)
        )

# ─── Duyuru ──────────────────────────────────────────────────────

@admin_r.message(StateFilter(Adm.broadcast))
async def adm_broadcast(msg: Message, state: FSMContext, bot: Bot) -> None:
    if not is_admin(msg.from_user.id):
        return
    if msg.text == "❌ İptal":
        await state.clear()
        await msg.answer("❌ İptal.", reply_markup=main_kb(msg.from_user.id))
        return
    await state.clear()
    users = await many("SELECT user_id FROM users WHERE is_banned=0")
    ok = fail = 0
    for u in users:
        try:
            await bot.send_message(u["user_id"], f"📢 <b>Duyuru:</b>\n\n{msg.text}")
            ok += 1
        except Exception:
            fail += 1
        await asyncio.sleep(0.05)
    await msg.answer(
        f"📢 <b>Duyuru Tamamlandı</b>\n\n"
        f"✅ Gönderildi: {ok}\n❌ Başarısız: {fail}",
        reply_markup=main_kb(msg.from_user.id)
    )

# ─── Ban / Unban ─────────────────────────────────────────────────

@admin_r.callback_query(F.data.startswith("adm_ban:"))
async def adm_ban(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    uid = int(call.data.split(":")[1])
    await exe("UPDATE users SET is_banned=1 WHERE user_id=?", (uid,))
    try:
        await bot.send_message(uid, "🚫 Hesabınız yasaklandı.")
    except Exception:
        pass
    await call.answer(f"🚫 {uid} yasaklandı", show_alert=True)


@admin_r.callback_query(F.data.startswith("adm_unban:"))
async def adm_unban(call: CallbackQuery, bot: Bot) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("🚫", show_alert=True)
        return
    uid = int(call.data.split(":")[1])
    await exe("UPDATE users SET is_banned=0 WHERE user_id=?", (uid,))
    try:
        await bot.send_message(uid, "✅ Hesabınızın yasağı kaldırıldı.")
    except Exception:
        pass
    await call.answer(f"✅ {uid} yasağı kaldırıldı", show_alert=True)

# ═══════════════════════════════════════════════════════════════════
#  KRİPTO MONİTÖR (arka plan görevi)
# ═══════════════════════════════════════════════════════════════════

async def crypto_monitor(bot: Bot) -> None:
    log.info("🔍 Kripto monitörü başlatıldı")
    while True:
        try:
            addrs = await many("""
                SELECT ca.*, d.id AS did, d.code, d.buyer_id, d.seller_id,
                       d.amount AS damount, d.currency AS dcur, d.method
                FROM crypto_addr ca
                JOIN deals d ON ca.deal_id = d.id
                WHERE ca.status = 'waiting'
                  AND d.status = 'payment_pending'
            """)
            for a in addrs:
                try:
                    bal = await get_balance(a["coin"], a["address"])
                    if bal >= float(a["expected"]) * 0.99:
                        await exe(
                            "UPDATE crypto_addr SET status='received', received=? WHERE id=?",
                            (bal, a["id"])
                        )
                        await exe(
                            "UPDATE deals SET status='confirmed' WHERE id=?",
                            (a["did"],)
                        )
                        log.info("✅ Kripto ödeme alındı: #%s %s %s", a["code"], bal, a["coin"])
                        # Alıcıya bildir
                        try:
                            await bot.send_message(
                                a["buyer_id"],
                                f"✅ <b>Ödemeniz Alındı!</b>\n\n"
                                f"Anlaşma: <b>#{a['code']}</b>\n"
                                f"💰 Alınan: <b>{bal:.6f} {a['coin']}</b>\n\n"
                                f"📦 Ürün/hizmeti teslim alınca butona basın:",
                                reply_markup=ikb(
                                    [("✅ Teslim Aldım — Ödemeyi Onayla", f"release:{a['did']}")],
                                    [("⚠️ Sorun Var — Dispute Aç",         f"dispute:{a['did']}")]
                                )
                            )
                        except Exception:
                            pass
                        # Satıcıya bildir
                        try:
                            await bot.send_message(
                                a["seller_id"],
                                f"🔔 <b>Alıcı Ödemesi Doğrulandı!</b>\n\n"
                                f"Anlaşma: <b>#{a['code']}</b>\n"
                                f"✅ Ödeme blockchain'de onaylandı.\n"
                                f"⏳ Ürünü/hizmeti teslim edin — alıcı onayladıktan sonra ödemeniz yapılacak."
                            )
                        except Exception:
                            pass
                    elif bal > 0:
                        await exe(
                            "UPDATE crypto_addr SET received=? WHERE id=?",
                            (bal, a["id"])
                        )
                except Exception as e:
                    log.warning("Adres kontrol hatası: %s", e)
        except Exception as e:
            log.error("Monitor hatası: %s", e)
        await asyncio.sleep(MONITOR_SEC)

# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════

async def main() -> None:
    await db_init()
    log.info("✅ Veritabanı hazır: %s", DB_PATH)

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode="HTML")
    )
    dp = Dispatcher(storage=MemoryStorage())
    dp["bot"] = bot

    dp.include_router(admin_r)
    dp.include_router(user_r)

    asyncio.create_task(crypto_monitor(bot))

    log.info("🤖 Bot başlatıldı | Admin: %s | Komisyon: %%%.1f", ADMIN_IDS, FEE_PERCENT)
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())


if __name__ == "__main__":
    print("╔══════════════════════════════════════╗")
    print("║     ESCROW BOT v3.0 — Production     ║")
    print("╠══════════════════════════════════════╣")
    print("║ 1. BOT_TOKEN env değişkenini ayarla  ║")
    print("║ 2. ADMIN_IDS env değişkenini ayarla  ║")
    print("║ 3. /admin ile admin panele gir       ║")
    print("╚══════════════════════════════════════╝")
    asyncio.run(main())
