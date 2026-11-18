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
pip install streamlit torch transformers pandas scikit-learn datasets
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

## Project structure

```
scam_detector/
├── src/
│   ├── app.py       # Streamlit web application
│   ├── predict.py   # Inference pipeline
│   ├── train.py     # Model training
│   └── explain.py   # SHAP explainability (optional)
├── models/
│   └── scam_detector/   # Saved model artifacts (not in git)
└── combined_dataset.csv # Training data (not in git)
```

## Optional: model explainability

`src/explain.py` uses SHAP to visualize which words influenced a prediction. Install `shap` and point `MODEL_DIR` at `models/scam_detector/` before running.
