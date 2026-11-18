# src/analyzer.py
"""Forensics engine for the Telegram Security Guard.

Hybrid scoring: the fine-tuned DistilBERT probability (index 1 = scam/spam)
plus bounded boosts from deterministic signals (lookalike domains, APK
payloads, shortened links, manipulation tactics).

Public API:
    analyze_text_async(text, resolve_links=True) -> dict   (use from async code / the bot)
    analyze_text(text, resolve_links=True) -> dict         (sync wrapper: CLI, tests, Streamlit)
    extract_text_from_image(image_bytes) -> str            (RapidOCR, no Tesseract)
    transcribe_audio(audio_path) -> str                    (faster-whisper tiny, CPU int8)
"""
from __future__ import annotations

import asyncio
import re
from difflib import SequenceMatcher
from urllib.parse import urlsplit

import httpx
import torch

from predict import _get_model  # reuse the existing singleton loader (same model as app.py)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
MAX_LENGTH = 128  # must match training (train.py MAX_LENGTH)
SCAM_INDEX = 1  # train.py label_map: spam/scam -> 1, ham/legit -> 0

SAFE_BELOW = 40.0
HIGH_RISK_ABOVE = 75.0

LOOKALIKE_THRESHOLD = 0.78
HARD_SIGNAL_FLOOR = 80.0  # lookalike domain / APK payload force HIGH_RISK
MAX_HEURISTIC_BOOST = 35.0

PROTECTED_DOMAINS = [
    "hdfcbank.com", "sbi.co.in", "icicibank.com", "axisbank.com", "kotak.com",
    "npci.org.in", "paytm.com", "phonepe.com", "parivahan.gov.in", "incometax.gov.in",
]
# Official sister domains that must never be flagged as lookalikes.
OFFICIAL_ALLOWLIST = set(PROTECTED_DOMAINS) | {
    "onlinesbi.sbi", "sbi.bank.in", "sbicard.com", "hdfc.bank.in", "icici.bank.in",
    "axis.bank.in", "kotak.bank.in", "paytmbank.com", "echallan.parivahan.gov.in",
    "india.gov.in", "gov.in", "nic.in", "cybercrime.gov.in", "sancharsaathi.gov.in",
}
# Brand keywords (>=5 chars to avoid noise) — if a non-official domain contains one, it's impersonation.
BRAND_KEYWORDS = {
    "hdfcbank": "hdfcbank.com", "icicibank": "icicibank.com", "axisbank": "axisbank.com",
    "kotak": "kotak.com", "paytm": "paytm.com", "phonepe": "phonepe.com",
    "parivahan": "parivahan.gov.in", "incometax": "incometax.gov.in", "onlinesbi": "sbi.co.in",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly", "bitly.com", "s.id", "v.gd",
    "short.gy", "shrtco.de", "wa.link", "surl.li", "u.to", "clck.ru",
}

MULTI_PART_SUFFIXES = {
    "co.in", "gov.in", "org.in", "net.in", "ac.in", "res.in", "nic.in", "bank.in",
    "firm.in", "gen.in", "ind.in", "co.uk", "com.au",
}

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------
_TLDS = r"(?:com|in|ly|co|org|net|xyz|top|info|app|link|me|io|site|online|live|click|club|vip|shop|cc|gl|gd|at|li|to|ru|de|id|bank|sbi)"
URL_RE = re.compile(
    rf"""(?ix)
    (?<![@\w.-])                                   # not part of an email/UPI handle
    (?:https?://[^\s<>"']+                          # explicit scheme
      |www\.[^\s<>"']+                              # www.
      |(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+{_TLDS}\b(?:/[^\s<>"']*)?   # bare domain
    )"""
)
UPI_RE = re.compile(r"(?<![\w.-])[\w.-]+@[A-Za-z]+\b(?!\.)")  # handle@bank (excludes emails)
PHONE_RE = re.compile(r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)")
APK_RE = re.compile(r"[^\s<>\"']*\.apk\b", re.I)

_NEG = r"(?<!not )(?<!n't )(?<!never )"
TACTIC_PATTERNS: dict[str, list[str]] = {
    "False Urgency": [
        r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bwithin \d+ ?(hours?|hrs?|minutes?|mins?|days?)\b",
        r"\btoday\b", r"\btonight\b", r"\bexpir(e|es|ed|ing|y)\b", r"\b(will be|has been|is) (blocked|suspended|deactivated|closed|disconnected|frozen|cancelled)\b",
        r"\blast (chance|date|day|warning|reminder)\b", r"\bact now\b", r"\bfinal (notice|warning)\b",
        r"\bdeadline\b", r"\bavoid (penalty|legal action|suspension|disconnection)\b",
    ],
    "Authority Impersonation": [
        r"\b(rbi|reserve bank|sebi|trai|cbi|ed|npci|uidai|police|cyber ?cell|customs|court|income ?tax|it department)\b",
        r"\b(hdfc|sbi|icici|axis|kotak|paytm|phonepe|gpay|google pay|bhim)\b",
        r"\b(kyc|pan ?card|aadha?a?r)\b", r"\b(e-?challan|challan|parivahan|rto|traffic police)\b",
        r"\b(electricity|power) (board|bill|department)\b", r"\bcustomer (care|support|service)\b",
        r"\b(govt|government|ministry)\b", r"\bfedex|dhl|courier\b",
    ],
    "Financial / Job Lure": [
        r"\b(won|winner|win|prize|lottery|lucky draw|jackpot)\b", r"\b(cashback|reward|refund|bonus|gift)\b",
        r"\b(part[- ]time|work from home|wfh|daily (income|payout|earning)|earn (rs\.?|₹|inr)?\s?\d)",
        r"\b(investment|trading|crypto|double your|guaranteed returns?)\b", r"\bloan (approved|sanctioned|offer)\b",
        r"\b(rs\.?|₹|inr)\s?\d[\d,]*\s?(credited|to be credited|will be credited)\b", r"\b(youtube|instagram) (likes|task)\b",
    ],
    "Malicious APK": [
        r"\.apk\b", r"\b(download|install) (the |this |our )?(app|apk|application|file)\b",
        r"\b(anydesk|teamviewer|quicksupport|rustdesk)\b",
    ],
    "Payment / PIN Trap": [
        r"\b(enter|share|provide|send|tell)\b.{0,25}\b(upi )?(pin|mpin)\b.{0,30}\b(receive|get|claim|credit)",
        r"\b(approve|accept)\b.{0,25}\b(collect|payment) request\b", r"\bscan (the|this) qr\b.{0,40}\b(receive|get|claim)\b",
        r"\bpay (rs\.?|₹|inr)?\s?\d+.{0,30}\b(to (receive|unlock|activate|release)|processing fee|registration fee)\b",
        r"\b(pay|send|transfer|deposit)\b.{0,30}\b(verification|processing|registration|activation|unlock(ing)?|refundable|security) (fee|charges?|deposit|amount)\b",
    ],
    "Credential Harvesting": [
        rf"{_NEG}\b(share|send|tell|provide|forward|update|verify) (your |the |this )?(otp|cvv|password|pin|card details|net ?banking)\b",
        r"\bclick (here|the link|below)\b.{0,40}\b(update|verify|login|log in|kyc|reactivate)\b",
        r"\b(update|complete|verify) (your )?(kyc|pan|aadha?a?r)\b",
    ],
}
_COMPILED_TACTICS = {k: [re.compile(p, re.I) for p in v] for k, v in TACTIC_PATTERNS.items()}
# Markers of genuine transactional SMS (OTP, debit/credit alerts, bills, deliveries).
# The fine-tuned model over-flags these (its "ham" training data is mostly personal chat),
# so they dampen an *uncorroborated* model score.
LEGIT_MARKERS = {
    "otp_warning": r"\b(do not|don't|never) (share|disclose)\b",
    "otp_format": r"^\s*\d{4,8} is (your|the) (otp|one[- ]time password|verification code|code)\b",
    "masked_account": r"\b(a/?c|acct|account|card)\b.{0,15}\b(x{2,}|\*{2,})\d{3,4}\b",
    "balance": r"\b(avl\.?|available|avbl\.?) ?(bal|balance)\b",
    "txn_alert": r"\b(debited|credited|withdrawn|spent) (from|to|on|by)\b",
    "sender_signoff": r"[-–]\s?[A-Z][A-Za-z&. ]{1,25}$",
    "delivery": r"\border\b.{0,30}\b(shipped|dispatched|delivered|placed|out for delivery)\b",
    "bill_due": r"\b(bill|payment|emi)\b.{0,40}\bdue (on|by|date)\b",
    "official_channel": r"\b(official (app|website)|visit (your )?(nearest )?branch)\b",
}
_COMPILED_LEGIT = {k: re.compile(p, re.I | re.M) for k, p in LEGIT_MARKERS.items()}
# Tactics strong enough on their own to corroborate a high model score.
CORROBORATING_TACTICS = {"False Urgency", "Financial / Job Lure", "Malicious APK", "Payment / PIN Trap", "Credential Harvesting"}
UNCORROBORATED_CAP = 55.0   # model alone can at most say SUSPICIOUS
LEGIT_DAMPEN_FACTOR = 0.25  # uncorroborated + transactional markers
LEGIT_DAMPEN_CAP = 30.0

TACTIC_BOOST = {
    "False Urgency": 10.0, "Authority Impersonation": 8.0, "Financial / Job Lure": 10.0,
    "Malicious APK": 20.0, "Payment / PIN Trap": 20.0, "Credential Harvesting": 15.0,
}

# ---------------------------------------------------------------------------
# Model inference
# ---------------------------------------------------------------------------
_get_model()  # warm the singleton once at import so the first message isn't slow


def model_scam_probability(text: str) -> float:
    tokenizer, model = _get_model()
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=MAX_LENGTH)
    with torch.no_grad():
        probs = torch.softmax(model(**inputs).logits, dim=-1)[0]
    return round(float(probs[SCAM_INDEX]) * 100, 2)


# ---------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------
def _dedupe(items):
    seen, out = set(), []
    for i in items:
        k = i.lower()
        if k not in seen:
            seen.add(k)
            out.append(i)
    return out


def extract_entities(text: str) -> dict:
    urls = [u.rstrip(".,!?;:)]}'\"") for u in URL_RE.findall(text)]
    upi = [u for u in UPI_RE.findall(text)]
    phones = [re.sub(r"[\s-]", "", p) for p in PHONE_RE.findall(text)]
    apks = [a.rstrip(".,!?;:)") for a in APK_RE.findall(text)]
    return {
        "urls": _dedupe(urls),
        "upi_ids": _dedupe(upi),
        "phones": _dedupe(phones),
        "apks": _dedupe(apks),
    }


# ---------------------------------------------------------------------------
# Domains / links
# ---------------------------------------------------------------------------
def _normalize_url(url: str) -> str:
    return url if re.match(r"(?i)^https?://", url) else "http://" + url


def _host(url: str) -> str:
    host = (urlsplit(_normalize_url(url)).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def registered_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_official(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in OFFICIAL_ALLOWLIST)


def check_lookalike(host: str) -> tuple[str | None, float]:
    """Return (impersonated_domain, similarity) or (None, best_similarity)."""
    if not host or _is_official(host):
        return None, 1.0 if host else 0.0
    reg = registered_domain(host)
    best_domain, best = None, 0.0
    for brand in PROTECTED_DOMAINS:
        s = SequenceMatcher(None, reg, brand).ratio()
        if s > best:
            best_domain, best = brand, s
    if best >= LOOKALIKE_THRESHOLD:
        return best_domain, round(best, 3)
    # brand keyword embedded in a non-official domain (e.g. hdfcbank.com.secure-login.xyz, parivahan-challan.in)
    compact = host.replace("-", "")
    for kw, brand in BRAND_KEYWORDS.items():
        if kw in compact:
            return brand, round(max(best, SequenceMatcher(None, reg, brand).ratio()), 3)
    return None, round(best, 3)


async def _resolve(client: httpx.AsyncClient, url: str) -> tuple[str, str | None]:
    """Follow redirects without downloading bodies or executing JS. Returns (final_url, error)."""
    try:
        async with client.stream("GET", _normalize_url(url)) as resp:
            return str(resp.url), None
    except Exception as e:  # network errors, timeouts, TLS failures — never crash analysis
        return _normalize_url(url), type(e).__name__


async def analyze_links(urls: list[str], resolve: bool = True) -> list[dict]:
    results = []
    to_resolve = [u for u in urls if registered_domain(_host(u)) in SHORTENERS or _host(u) in SHORTENERS]
    resolved: dict[str, tuple[str, str | None]] = {}
    if resolve and to_resolve:
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=3.0, max_redirects=8,
            headers={"User-Agent": "Mozilla/5.0 (Linux; Android 13) ScamShield/1.0"},
        ) as client:
            outs = await asyncio.gather(*(_resolve(client, u) for u in to_resolve))
        resolved = dict(zip(to_resolve, outs))

    for url in urls:
        host = _host(url)
        shortened = url in to_resolve
        final_url, error = resolved.get(url, (_normalize_url(url), None if not shortened or resolve else "not_resolved"))
        final_host = _host(final_url)
        lookalike_of, similarity = check_lookalike(final_host)
        results.append({
            "original": url,
            "final_url": final_url,
            "final_domain": final_host,
            "shortened": shortened,
            "resolve_error": error,
            "lookalike_of": lookalike_of,
            "similarity": similarity,
            "is_apk": bool(APK_RE.search(final_url) or APK_RE.search(url)),
            "official": _is_official(final_host),
        })
    return results


# ---------------------------------------------------------------------------
# Tactics
# ---------------------------------------------------------------------------
def profile_tactics(text: str, entities: dict, links: list[dict]) -> list[str]:
    tactics = [name for name, pats in _COMPILED_TACTICS.items() if any(p.search(text) for p in pats)]
    if (entities["apks"] or any(l["is_apk"] for l in links)) and "Malicious APK" not in tactics:
        tactics.append("Malicious APK")
    if any(l["lookalike_of"] for l in links) and "Authority Impersonation" not in tactics:
        tactics.append("Authority Impersonation")
    return tactics


def _verdict(p: float) -> str:
    if p < SAFE_BELOW:
        return "SAFE"
    if p > HIGH_RISK_ABOVE:
        return "HIGH_RISK"
    return "SUSPICIOUS"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
async def analyze_text_async(text: str, resolve_links: bool = True) -> dict:
    text = (text or "").strip()
    if not text:
        return {"verdict": "SAFE", "scam_probability": 0.0, "model_probability": 0.0,
                "heuristic_boost": 0.0, "corroborated": False, "legit_markers": [],
                "tactics": [], "entities": extract_entities(""),
                "links": [], "warnings": ["Empty message — nothing to analyze."], "text": ""}

    model_p = await asyncio.to_thread(model_scam_probability, text)
    entities = extract_entities(text)
    links = await analyze_links(entities["urls"], resolve=resolve_links)
    tactics = profile_tactics(text, entities, links)

    warnings: list[str] = []
    hard_signal = False
    for l in links:
        if l["shortened"] and l["final_url"] != _normalize_url(l["original"]):
            warnings.append(f"Shortened link {l['original']} → {l['final_url']}")
        elif l["shortened"] and l["resolve_error"]:
            warnings.append(f"Shortened link {l['original']} could not be resolved ({l['resolve_error']}) — destination hidden")
        if l["lookalike_of"]:
            hard_signal = True
            warnings.append(f"Lookalike domain {l['final_domain']} imitates {l['lookalike_of']} (similarity {l['similarity']:.2f})")
        if l["is_apk"]:
            hard_signal = True
            warnings.append(f"APK payload link: {l['final_url']}")
    if entities["apks"] and not any(l["is_apk"] for l in links):
        hard_signal = True
        warnings.append(f"APK file reference: {', '.join(entities['apks'])}")

    boost = sum(TACTIC_BOOST.get(t, 0.0) for t in tactics)
    if any(l["shortened"] for l in links):
        boost += 10.0
    if links and not all(l["official"] for l in links) and tactics:
        boost += 5.0  # unknown link + manipulation tactic
    boost = min(boost, MAX_HEURISTIC_BOOST)

    # Corroboration gate: the model alone can't push a message to HIGH_RISK.
    unknown_links = [l for l in links if not l["official"]]
    corroborated = bool(
        hard_signal or unknown_links or entities["upi_ids"]
        or CORROBORATING_TACTICS.intersection(tactics)
    )
    legit_markers = [k for k, p in _COMPILED_LEGIT.items() if p.search(text)]
    model_term = model_p
    if not corroborated:
        if legit_markers:
            model_term = min(model_p * LEGIT_DAMPEN_FACTOR, LEGIT_DAMPEN_CAP)
        else:
            model_term = min(model_p, UNCORROBORATED_CAP)

    score = min(100.0, model_term + boost)
    if hard_signal:
        score = max(score, HARD_SIGNAL_FLOOR)
    score = round(score, 2)

    return {
        "verdict": _verdict(score),
        "scam_probability": score,
        "model_probability": model_p,
        "heuristic_boost": round(boost, 2),
        "corroborated": corroborated,
        "legit_markers": legit_markers,
        "tactics": tactics,
        "entities": entities,
        "links": links,
        "warnings": warnings,
        "text": text,
    }


def analyze_text(text: str, resolve_links: bool = True) -> dict:
    """Sync wrapper. Do not call from inside a running event loop — use analyze_text_async there."""
    return asyncio.run(analyze_text_async(text, resolve_links=resolve_links))


# ---------------------------------------------------------------------------
# Multi-modal extractors (lazy singletons — loaded on first use)
# ---------------------------------------------------------------------------
_ocr = None
_whisper = None


def extract_text_from_image(image_bytes: bytes) -> str:
    global _ocr
    if _ocr is None:
        from rapidocr import RapidOCR
        _ocr = RapidOCR()
    result = _ocr(image_bytes)
    txts = getattr(result, "txts", None) or ()
    return " ".join(t.strip() for t in txts if t and t.strip())


def transcribe_audio(audio_path: str) -> str:
    """Speech -> English text. task='translate' turns Hindi/regional speech into English for the English classifier."""
    global _whisper
    if _whisper is None:
        from faster_whisper import WhisperModel
        _whisper = WhisperModel("tiny", device="cpu", compute_type="int8")
    segments, _info = _whisper.transcribe(audio_path, task="translate", beam_size=1, vad_filter=True)
    return " ".join(s.text.strip() for s in segments).strip()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    import sys

    msg = " ".join(sys.argv[1:]) or input("Message to analyze: ")
    print(json.dumps(analyze_text(msg), indent=2, ensure_ascii=False))
