# src/bot.py
"""Telegram Security Guard — multi-modal scam analysis bot.

Send / forward a text, a screenshot, or a voice note; get a forensic verdict card.
Non-SAFE verdicts get two action buttons: a safe counter-reply and a 1930 / Chakshu report draft.

Run:  cd src && python bot.py      (needs TELEGRAM_BOT_TOKEN in .env or the environment)
"""
from __future__ import annotations

import asyncio
import html
import logging
import os
import tempfile
import uuid
from collections import OrderedDict
from datetime import datetime, timezone, timedelta
from pathlib import Path

from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (
    ApplicationBuilder, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters,
)

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
load_dotenv(Path(__file__).resolve().parent / ".env")

from analyzer import analyze_text_async, extract_text_from_image, transcribe_audio  # noqa: E402  (loads model)

logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)  # don't log bot-API URLs (they contain the token)
log = logging.getLogger("security_guard")

IST = timezone(timedelta(hours=5, minutes=30))
MAX_CACHED_RESULTS = 500  # in-memory only, no database
MAX_TG_TEXT = 4000

BADGES = {"SAFE": "🟢 SAFE", "SUSPICIOUS": "🟡 SUSPICIOUS", "HIGH_RISK": "🔴 HIGH RISK"}
TACTIC_ICONS = {
    "False Urgency": "⏰", "Authority Impersonation": "🎩", "Financial / Job Lure": "💰",
    "Malicious APK": "📦", "Payment / PIN Trap": "🔐", "Credential Harvesting": "🎣",
}

# ---------------------------------------------------------------------------
# In-memory result store for callback buttons (callback_data max 64 bytes)
# ---------------------------------------------------------------------------
def _store(context: ContextTypes.DEFAULT_TYPE, payload: dict) -> str:
    cache: OrderedDict = context.bot_data.setdefault("results", OrderedDict())
    key = uuid.uuid4().hex[:12]
    cache[key] = payload
    while len(cache) > MAX_CACHED_RESULTS:
        cache.popitem(last=False)
    return key


def _load(context: ContextTypes.DEFAULT_TYPE, key: str) -> dict | None:
    return context.bot_data.get("results", {}).get(key)


# ---------------------------------------------------------------------------
# Formatting (HTML parse mode — every dynamic value is escaped)
# ---------------------------------------------------------------------------
e = html.escape


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def format_verdict_card(result: dict, source: str = "text", extracted: str | None = None) -> str:
    v = result["verdict"]
    lines = [
        f"<b>{BADGES[v]}</b>",
        f"Scam likelihood: <b>{result['scam_probability']:.1f}%</b>",
        f"<i>Model {result['model_probability']:.1f}% · heuristics +{result['heuristic_boost']:.0f}"
        f"{'' if result.get('corroborated', True) else ' · uncorroborated, capped'}</i>",
    ]
    if extracted is not None:
        label = "📷 Text read from image" if source == "image" else "🎙️ Transcript"
        lines += ["", f"<b>{label}:</b>", f"<blockquote>{e(_truncate(extracted, 600)) or '<i>(nothing readable)</i>'}</blockquote>"]

    if result["tactics"]:
        lines += ["", "<b>🧠 Manipulation tactics</b>"]
        lines += [f"{TACTIC_ICONS.get(t, '•')} {e(t)}" for t in result["tactics"]]

    ent = result["entities"]
    if ent["upi_ids"] or ent["phones"] or result["links"] or ent["apks"]:
        lines += ["", "<b>🔎 Extracted entities</b>"]
        if ent["upi_ids"]:
            lines.append("💳 UPI: " + ", ".join(f"<code>{e(u)}</code>" for u in ent["upi_ids"]))
        if ent["phones"]:
            lines.append("📞 Phone: " + ", ".join(f"<code>{e(p)}</code>" for p in ent["phones"]))
        for l in result["links"]:
            if l["shortened"] and not l["resolve_error"] and l["final_url"] != l["original"]:
                lines.append(f"🔗 <code>{e(l['original'])}</code> → <code>{e(l['final_url'])}</code>")
            else:
                lines.append(f"🔗 <code>{e(l['original'])}</code>")
        for a in ent["apks"]:
            if not any(a in l["original"] for l in result["links"]):
                lines.append(f"📦 <code>{e(a)}</code>")

    if result["warnings"]:
        lines += ["", "<b>⚠️ Warnings</b>"] + [f"• {e(w)}" for w in result["warnings"]]

    lines.append("")
    if v == "SAFE":
        lines.append("✅ No strong scam signals. Reminder: banks never ask for OTP, PIN or CVV.")
    else:
        lines.append("🚫 Do not click links, install apps, pay, or share OTP/PIN. Use the buttons below.")
    return _truncate("\n".join(lines), MAX_TG_TEXT)


# ---------------------------------------------------------------------------
# Counter-reply (zero PII — never reveals anything about the user)
# ---------------------------------------------------------------------------
def build_counter_reply(result: dict) -> str:
    tactics = set(result["tactics"])
    brand = next((l["lookalike_of"] for l in result["links"] if l["lookalike_of"]), None)
    official = f"@{brand}" if brand else "your organisation's official domain"
    parts = []
    if "Authority Impersonation" in tactics or brand:
        parts.append(
            f"Before I do anything, please email me from your official {official} address with your "
            "employee ID and an official case/reference number. I will verify it by calling the number "
            "printed on my card / the official website, not the one you sent."
        )
    if "Payment / PIN Trap" in tactics:
        parts.append("Receiving money never requires a PIN or a fee. Share an official transaction reference and I will check it with my bank directly.")
    if "Credential Harvesting" in tactics:
        parts.append("I do not share OTPs, PINs, passwords or card details over chat or calls. I will log in through the official app myself to check.")
    if "Financial / Job Lure" in tactics:
        parts.append("Please send the official offer/claim letter from a company-domain email along with the company CIN or GST number so I can verify it on the MCA portal.")
    if "Malicious APK" in tactics:
        parts.append("I only install apps from the Play Store by the verified official developer. Send the Play Store link listed on the official website.")
    if not parts or tactics == {"False Urgency"}:
        parts.append("I will verify this independently through official channels at my convenience.")
    parts.append("Until then, I will not click any link or make any payment.")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# 1930 / Chakshu report draft
# ---------------------------------------------------------------------------
_CATEGORY = [
    ("Malicious APK", "Malicious link / APK (remote access / banking malware)"),
    ("Payment / PIN Trap", "UPI fraud — collect request / PIN to receive money"),
    ("Credential Harvesting", "KYC / OTP / credential phishing"),
    ("Authority Impersonation", "Impersonation of bank / government / company official"),
    ("Financial / Job Lure", "Fake job / lottery / investment / reward offer"),
]


def build_report(result: dict, meta: dict) -> str:
    tactics = result["tactics"]
    category = next((c for t, c in _CATEGORY if t in tactics), "Suspected fraud communication")
    ent = result["entities"]
    links = result["links"]
    url_lines = [
        f"  - {l['original']}" + (f"  →  {l['final_url']}" if l["shortened"] and not l["resolve_error"] else "")
        + (f"  [LOOKALIKE of {l['lookalike_of']}]" if l["lookalike_of"] else "")
        + ("  [APK]" if l["is_apk"] else "")
        for l in links
    ]
    body = [
        "CYBER FRAUD INCIDENT REPORT (draft)",
        "===================================",
        f"Date/time received : {meta['received']}",
        f"Medium             : {meta['medium']}",
        f"Suspected category : {category}",
        f"Risk assessment    : {result['verdict']} ({result['scam_probability']:.1f}%)",
        f"Tactics observed   : {', '.join(tactics) or 'None detected'}",
        "",
        "Suspect identifiers",
        "-------------------",
        "Phone numbers : " + (", ".join(ent["phones"]) or "None found"),
        "UPI IDs       : " + (", ".join(ent["upi_ids"]) or "None found"),
        "URLs          :" + ("\n" + "\n".join(url_lines) if url_lines else " None found"),
        "APK files     : " + (", ".join(ent["apks"]) or "None found"),
        "",
        "Message content (verbatim)",
        "--------------------------",
        _truncate(result["text"], 1800),
        "",
        "Financial loss : [None / amount + date + transaction ID]",
        "Victim details : [fill in on the portal — not included here]",
    ]
    return "\n".join(body)


REPORT_GUIDE = (
    "<b>Where to file</b>\n"
    "• <b>Money lost?</b> Call <b>1930</b> immediately (first hours matter), then file at "
    "<a href=\"https://cybercrime.gov.in\">cybercrime.gov.in</a> → Report Cyber Crime → Financial Fraud.\n"
    "• <b>No money lost?</b> Report the number/message on "
    "<a href=\"https://sancharsaathi.gov.in\">Sanchar Saathi</a> → Chakshu.\n"
    "Copy the draft above and paste it into the description field."
)


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------
async def _respond(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str,
                   source: str = "text", extracted: str | None = None) -> None:
    msg = update.effective_message
    if not text.strip():
        await msg.reply_text("I couldn't find any text to analyze in that message.")
        return

    await context.bot.send_chat_action(msg.chat_id, "typing")
    result = await analyze_text_async(text)

    forwarded = bool(getattr(msg, "forward_origin", None))
    received = (msg.forward_origin.date if forwarded else msg.date) or datetime.now(timezone.utc)
    meta = {
        "received": received.astimezone(IST).strftime("%d-%b-%Y %H:%M IST"),
        "medium": {"text": "Text message", "image": "Screenshot / image", "voice": "Voice note / audio"}[source]
        + (" (forwarded on Telegram)" if forwarded else " (shared on Telegram)"),
    }

    markup = None
    if result["verdict"] != "SAFE":
        key = _store(context, {"result": result, "meta": meta})
        markup = InlineKeyboardMarkup([[
            InlineKeyboardButton("🎭 Safe Counter-Reply", callback_data=f"cr:{key}"),
            InlineKeyboardButton("📋 1930 / Chakshu Report", callback_data=f"rp:{key}"),
        ]])

    await msg.reply_text(
        format_verdict_card(result, source, extracted), parse_mode=ParseMode.HTML,
        reply_markup=markup, disable_web_page_preview=True,  # never preview scam links
    )
    log.info("verdict=%s score=%.1f source=%s", result["verdict"], result["scam_probability"], source)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(
        "🛡️ <b>Security Guard</b>\n\n"
        "Forward or send me a suspicious <b>message</b>, <b>screenshot</b> or <b>voice note</b> and I'll check it for:\n"
        "• scam language (AI model)\n• fake / lookalike bank & government links\n"
        "• hidden shortened links and APK malware\n• UPI IDs and phone numbers to report\n\n"
        "<i>Messages are analyzed in memory and not stored.</i>",
        parse_mode=ParseMode.HTML,
    )


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _respond(update, context, update.effective_message.text or "")


async def on_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    await context.bot.send_chat_action(msg.chat_id, "typing")
    tg_file = await (msg.photo[-1].get_file() if msg.photo else msg.document.get_file())
    image_bytes = bytes(await tg_file.download_as_bytearray())
    ocr_text = await asyncio.to_thread(extract_text_from_image, image_bytes)
    combined = " ".join(filter(None, [msg.caption, ocr_text]))
    await _respond(update, context, combined, source="image", extracted=ocr_text)


async def on_voice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    media = msg.voice or msg.audio
    await context.bot.send_chat_action(msg.chat_id, "typing")
    suffix = Path(getattr(media, "file_name", None) or "voice.ogg").suffix or ".ogg"
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="sg_audio_")
    os.close(fd)
    try:
        tg_file = await media.get_file()
        await tg_file.download_to_drive(path)
        transcript = await asyncio.to_thread(transcribe_audio, path)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    combined = " ".join(filter(None, [msg.caption, transcript]))
    await _respond(update, context, combined, source="voice", extracted=transcript)


async def on_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    action, _, key = (query.data or "").partition(":")
    stored = _load(context, key)
    if not stored:
        await query.answer("This analysis has expired — please send the message again.", show_alert=True)
        return
    await query.answer()
    result, meta = stored["result"], stored["meta"]
    if action == "cr":
        await query.message.reply_text(
            "🎭 <b>Safe counter-reply</b> (contains no personal info — copy & send, or just block):\n\n"
            f"<code>{e(build_counter_reply(result))}</code>",
            parse_mode=ParseMode.HTML,
        )
    elif action == "rp":
        await query.message.reply_text(
            f"<pre>{e(build_report(result, meta))}</pre>\n\n{REPORT_GUIDE}",
            parse_mode=ParseMode.HTML, disable_web_page_preview=True,
        )


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Handler error", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text("⚠️ Sorry, I couldn't analyze that. Please try again.")
        except Exception:
            pass


def build_app():
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("TELEGRAM_BOT_TOKEN is not set. Add it to .env in the project root (see README).")
    app = ApplicationBuilder().token(token).build()
    app.add_handler(CommandHandler(["start", "help"], start))
    app.add_handler(MessageHandler(filters.PHOTO | filters.Document.IMAGE, on_photo))
    app.add_handler(MessageHandler(filters.VOICE | filters.AUDIO, on_voice))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_handler(CallbackQueryHandler(on_button, pattern=r"^(cr|rp):"))
    app.add_error_handler(on_error)
    return app


def main() -> None:
    log.info("Security Guard starting (polling)…")
    build_app().run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
