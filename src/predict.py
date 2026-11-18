# src/predict.py
import os
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "scam_detector"))

_tokenizer = None
_model = None


def _get_model():
    global _tokenizer, _model
    if _model is None:
        _tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
        _model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
        _model.eval()
    return _tokenizer, _model


def predict(text: str):
    tokenizer, model = _get_model()
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=128)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        pred = torch.argmax(probs, dim=1).item()
        label = "Scam / Spam ❌" if pred == 1 else "Safe / Genuine ✅"
        confidence = probs[0][pred].item()
    return {"label": label, "confidence": round(confidence * 100, 2)}

if __name__ == "__main__":
    text = input("Enter a message to classify: ")
    result = predict(text)
    print(result)
