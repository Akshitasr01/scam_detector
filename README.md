# AI Scam Shield

A scam/spam text classifier built with **DistilBERT**, **PyTorch**, and **Hugging Face Transformers**, with a **Streamlit** web UI for real-time predictions.

## Prerequisites

- Python 3.10+
- A trained model in `models/scam_detector/` (see [Training](#training) if missing)

## Setup

```powershell
cd c:\Projects\scam_detector
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If `.venv` already exists with dependencies installed, activate it and skip the install step.

## Run the web app

```powershell
cd c:\Projects\scam_detector
.\.venv\Scripts\Activate.ps1
cd src
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501) in your browser.

## CLI prediction

```powershell
cd c:\Projects\scam_detector\src
python predict.py
```

Enter a message when prompted; the script prints the label and confidence score.

## Training

The training script expects a CSV with `text` and `label` columns (`spam` / `ham`).

Update `DATA_PATH` in `src/train.py` if needed. To use the dataset in the project root:

```python
DATA_PATH = os.path.join("..", "combined_dataset.csv")
```

Then run:

```powershell
cd c:\Projects\scam_detector\src
python train.py
```

The fine-tuned model is saved to `models/scam_detector/`, which `predict.py` and `app.py` load automatically.

## Telegram Security Guard

A Telegram bot that checks forwarded messages, screenshots and voice notes for Indian scam patterns (bank KYC, UPI collect, e-challan APKs, fake jobs) and helps the user respond and report.

### Architecture

```
Telegram ──► bot.py (python-telegram-bot v22, polling)
               ├─ text / forwarded ───────────────────────┐
               ├─ photo / screenshot ─► RapidOCR ─────────┤
               └─ voice / audio ──► faster-whisper (tiny) ┤
                                                          ▼
                                analyzer.py  analyze_text_async()
                                 ├─ DistilBERT scam probability (models/scam_detector, index 1 = scam)
                                 ├─ regex entities: URLs, UPI IDs, +91 phones, .apk
                                 ├─ httpx link unshortener (redirects only, no JS)
                                 ├─ difflib lookalike check vs. bank / UPI / gov domains
                                 ├─ tactic profiler (urgency, impersonation, lure, APK, PIN trap, phishing)
                                 └─ hybrid score ─► SAFE < 40 ≤ SUSPICIOUS ≤ 75 < HIGH_RISK
                                                          ▼
               verdict card + buttons: 🎭 Safe Counter-Reply · 📋 1930 / Chakshu Report Draft
```

**Hybrid scoring.** Score = model probability + tactic/link boosts (capped at +35). A lookalike domain or APK payload forces at least 80 (HIGH_RISK). Because the model was trained on chat-style "ham", it over-flags genuine bank/company SMS. To correct for this, if nothing backs up the model's verdict (no unknown link, UPI ID, APK or strong tactic), its score is capped at 55. It is dampened further when the message looks transactional (OTP warning, masked account, "Avl bal", sender sign-off).

Everything runs locally on CPU. No paid APIs, no Tesseract/ffmpeg, no database: analyses are kept in memory only for the action buttons.

### Setup

1. `pip install -r requirements.txt`
2. Create a bot with [@BotFather](https://t.me/BotFather) (`/newbot`) and copy the token.
3. Create `.env` in the project root (it is git-ignored):
   ```
   TELEGRAM_BOT_TOKEN=123456789:AAH...
   ```
4. Run:
   ```powershell
   cd src
   python bot.py
   ```
   The first screenshot downloads the OCR models; the first voice note downloads Whisper `tiny` (~75 MB). Voice notes are translated to English before scoring.

Analyze from the command line without Telegram: `python analyzer.py "your message"`.

### Tests

```powershell
cd src
python test_suite.py
```
Five offline scenarios: fake KYC SMS with shortened link, `hdfcbank-kyc.com` lookalike, `.apk` e-challan, UPI collect/PIN scam, and a legitimate bank OTP (must stay SAFE).

### Example verdict

```
🔴 HIGH RISK
Scam likelihood: 100.0%
Model 100.0% · heuristics +35

🧠 Manipulation tactics
⏰ False Urgency
🎩 Authority Impersonation
📦 Malicious APK

🔎 Extracted entities
📞 Phone: +919123456780
🔗 http://parivahan-echallan.top/mParivahan.apk

⚠️ Warnings
• Lookalike domain parivahan-echallan.top imitates parivahan.gov.in (uses the brand name on a non-official domain)
• APK payload link: http://parivahan-echallan.top/mParivahan.apk

🚫 Do not click links, install apps, pay, or share OTP/PIN. Use the buttons below.
[🎭 Safe Counter-Reply] [📋 1930 / Chakshu Report]
```

## Project structure

```
scam_detector/
├── requirements.txt
├── src/
│   ├── app.py         # Streamlit web application
│   ├── predict.py     # Inference pipeline
│   ├── analyzer.py    # Forensics engine (hybrid scoring, entities, links, OCR, speech)
│   ├── bot.py         # Telegram Security Guard
│   ├── test_suite.py  # Offline analyzer scenarios
│   ├── train.py       # Model training
│   └── explain.py     # SHAP explainability (optional)
├── models/
│   └── scam_detector/   # Saved model artifacts (not in git)
└── combined_dataset.csv # Training data (not in git)
```

## Optional: model explainability

`src/explain.py` uses SHAP to visualize which words influenced a prediction. Install `shap` and point `MODEL_DIR` at `models/scam_detector/` before running.
