# src/explain.py
import os
import shap
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_DIR = r"C:\Users\akshi\OneDrive\Desktop\spam\models\scam_detector"

tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
model.eval()

explainer = shap.Explainer(model, masker=tokenizer)

def explain_text(text):
    shap_values = explainer([text])
    shap.plots.text(shap_values[0])
