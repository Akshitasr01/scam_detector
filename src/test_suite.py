# src/test_suite.py
"""Offline end-to-end checks for analyzer.py (no network, no Telegram).

Run:  cd src && python test_suite.py      (exit code 1 if any scenario fails)
"""
from __future__ import annotations

import asyncio
import sys

import analyzer

# --- Offline link resolver: simulate shortener redirects, never touch the network ----------
FAKE_REDIRECTS = {
    "http://bit.ly/sbi-kyc-upd": "http://onlinesbi-kyc-update.xyz/login",
}


async def _fake_resolve(client, url):
    norm = analyzer._normalize_url(url)
    return FAKE_REDIRECTS.get(norm, norm), None


analyzer._resolve = _fake_resolve


def _has_lookalike(r, brand):
    return any(l["lookalike_of"] == brand for l in r["links"])


SCENARIOS = [
    {
        "name": "(a) Fake bank KYC SMS with shortened link",
        "text": "Dear SBI customer, your YONO account will be blocked today due to pending KYC. "
                "Update now: bit.ly/sbi-kyc-upd",
        "expect_verdict": "HIGH_RISK",
        "checks": {
            "link is marked shortened": lambda r: any(l["shortened"] for l in r["links"]),
            "unshortened to final domain": lambda r: any(l["final_domain"] == "onlinesbi-kyc-update.xyz" for l in r["links"]),
            "final domain flagged as SBI lookalike": lambda r: _has_lookalike(r, "sbi.co.in"),
            "False Urgency tactic": lambda r: "False Urgency" in r["tactics"],
        },
    },
    {
        "name": "(b) Lookalike domain hdfcbank-kyc.com",
        "text": "HDFC Bank: Your NetBanking access is suspended. Re-verify your PAN within 24 hours "
                "at https://hdfcbank-kyc.com/login to avoid permanent closure.",
        "expect_verdict": "HIGH_RISK",
        "checks": {
            "lookalike of hdfcbank.com": lambda r: _has_lookalike(r, "hdfcbank.com"),
            "similarity >= 0.78": lambda r: any(l["similarity"] >= 0.78 for l in r["links"]),
            "Authority Impersonation tactic": lambda r: "Authority Impersonation" in r["tactics"],
        },
    },
    {
        "name": "(c) Malicious .apk challan scam",
        "text": "Your vehicle e-challan of Rs 500 is pending. Pay today to avoid legal action. "
                "Download the mParivahan app: http://parivahan-echallan.top/mParivahan.apk or call +91 9123456780",
        "expect_verdict": "HIGH_RISK",
        "checks": {
            "APK detected": lambda r: bool(r["entities"]["apks"]) and any(l["is_apk"] for l in r["links"]),
            "Malicious APK tactic": lambda r: "Malicious APK" in r["tactics"],
            "phone extracted": lambda r: "+919123456780" in r["entities"]["phones"],
        },
    },
    {
        "name": "(d) UPI collect scam",
        "text": "Congratulations! You have received a cashback of Rs 2,000 from PhonePe. To receive the amount, "
                "approve the collect request and enter your UPI PIN. Request from cashback.reward@ybl",
        "expect_verdict": "HIGH_RISK",
        "checks": {
            "UPI ID extracted": lambda r: "cashback.reward@ybl" in r["entities"]["upi_ids"],
            "Payment / PIN Trap tactic": lambda r: "Payment / PIN Trap" in r["tactics"],
            "Financial lure tactic": lambda r: "Financial / Job Lure" in r["tactics"],
        },
    },
    {
        "name": "(e) Legitimate bank OTP",
        "text": "123456 is your OTP for HDFC Bank NetBanking login. Valid for 5 minutes. "
                "Do not share this OTP with anyone. -HDFC Bank",
        "expect_verdict": "SAFE",
        "checks": {
            "no links / UPI": lambda r: not r["links"] and not r["entities"]["upi_ids"],
            "no Credential Harvesting false positive": lambda r: "Credential Harvesting" not in r["tactics"],
            "transactional markers found": lambda r: "otp_warning" in r["legit_markers"],
        },
    },
]


async def run() -> int:
    failures = 0
    print(f"{'Scenario':<46} {'Expected':<10} {'Got':<10} {'Score':>6} {'Model':>6}  Result")
    print("-" * 96)
    for sc in SCENARIOS:
        r = await analyzer.analyze_text_async(sc["text"], resolve_links=True)
        failed = [] if r["verdict"] == sc["expect_verdict"] else [f"verdict {r['verdict']} != {sc['expect_verdict']}"]
        failed += [name for name, check in sc["checks"].items() if not check(r)]
        status = "PASS" if not failed else "FAIL"
        failures += bool(failed)
        print(f"{sc['name']:<46} {sc['expect_verdict']:<10} {r['verdict']:<10} "
              f"{r['scam_probability']:>6.1f} {r['model_probability']:>6.1f}  {status}")
        print(f"{'':<4}tactics: {', '.join(r['tactics']) or '-'}")
        for w in r["warnings"]:
            print(f"{'':<4}warning: {w}")
        for f in failed:
            print(f"{'':<4}FAILED: {f}")
    print("-" * 96)
    print(f"{len(SCENARIOS) - failures}/{len(SCENARIOS)} scenarios passed")
    return failures


if __name__ == "__main__":
    sys.exit(1 if asyncio.run(run()) else 0)
