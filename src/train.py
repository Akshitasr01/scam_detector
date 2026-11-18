# src/train.py
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from datasets import Dataset, DatasetDict
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments
)
import torch

# -----------------------------
# CONFIG
# -----------------------------
MODEL_NAME = "distilbert-base-uncased"  # ✅ fixed HF model ID
OUT_DIR = os.path.join("..", "models", "scam_detector")
DATA_PATH = r"C:\Users\akshi\OneDrive\Desktop\spam\combined_dataset.csv"
MAX_LENGTH = 128
TRAIN_BATCH = 8
EVAL_BATCH = 16
EPOCHS = 3
SEED = 42

# -----------------------------
# HELPER FUNCTIONS
# -----------------------------
def load_and_split_csv(path):
    df = pd.read_csv(path)
    assert "text" in df.columns and "label" in df.columns, "CSV must have 'text' and 'label' columns"

    # Normalize label text (lowercase)
    df["label"] = df["label"].astype(str).str.lower().str.strip()

    # Convert string labels to integers
    label_map = {
        "spam": 1,
        "ham": 0,
        "scam": 1,
        "not spam": 0,
        "not_spam": 0,
        "legit": 0
    }
    df["label"] = df["label"].map(label_map)

    # Handle any unmapped labels
    if df["label"].isnull().any():
        print("⚠️ Warning: Found unknown labels. Removing those rows.")
        df = df.dropna(subset=["label"])

    df["label"] = df["label"].astype(int)

    # Split dataset
    train_df, test_df = train_test_split(df, test_size=0.2, stratify=df["label"], random_state=SEED)
    return train_df.reset_index(drop=True), test_df.reset_index(drop=True)



def tokenize(batch, tokenizer):
    tokens = tokenizer(
        batch["text"],
        truncation=True,
        padding="max_length",
        max_length=MAX_LENGTH
    )
    tokens["labels"] = batch["label"]  # ✅ include labels so model can compute loss
    return tokens


def compute_metrics(p):
    preds = np.argmax(p.predictions, axis=1)
    labels = p.label_ids
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
    return {
        "accuracy": accuracy_score(labels, preds),
        "f1": f1_score(labels, preds),
        "precision": precision_score(labels, preds),
        "recall": recall_score(labels, preds),
    }

# -----------------------------
# MAIN
# -----------------------------
def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    # Load and split dataset
    train_df, test_df = load_and_split_csv(DATA_PATH)

    # Convert to HF Datasets
    dataset = DatasetDict({
        "train": Dataset.from_pandas(train_df),
        "test": Dataset.from_pandas(test_df)
    })

    # Tokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    dataset = dataset.map(lambda batch: tokenize(batch, tokenizer), batched=True)
    dataset.set_format(type="torch", columns=["input_ids", "attention_mask", "labels"])

    # Model
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

    # GPU check
    device = 0 if torch.cuda.is_available() else -1
    print("✅ Using device:", "GPU" if device == 0 else "CPU")

    # Training args
    training_args = TrainingArguments(
        output_dir=OUT_DIR,
        eval_strategy="epoch",  # ✅ fixed deprecation warning
        per_device_train_batch_size=TRAIN_BATCH,
        per_device_eval_batch_size=EVAL_BATCH,
        num_train_epochs=EPOCHS,
        save_strategy="epoch",
        weight_decay=0.01,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        logging_steps=50,
        report_to="none"
    )

    # Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["test"],
        compute_metrics=compute_metrics,
        tokenizer=tokenizer
    )

    # Train
    trainer.train()

    # Save model and tokenizer
    trainer.save_model(OUT_DIR)
    tokenizer.save_pretrained(OUT_DIR)
    print("✅ Model and tokenizer saved to:", OUT_DIR)


# -----------------------------
# RUN
# -----------------------------
if __name__ == "__main__":
    main()
