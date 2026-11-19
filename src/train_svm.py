# src/train_svm.py
"""Train a TF-IDF + Linear SVM scam classifier and compare it with the fine-tuned DistilBERT.

Uses the exact same label mapping, 80/20 stratified split and seed as train.py, so both
models are scored on identical test messages.

    python train_svm.py                      # train SVM, evaluate both models
    python train_svm.py --skip-bert          # SVM only (fast)
    python train_svm.py --data path/to.csv   # different dataset
"""
import argparse
import os
import time

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from train import SEED, load_and_split_csv  # same split as DistilBERT training

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATA = os.path.join(ROOT, "combined_dataset.csv")
SVM_OUT = os.path.join(ROOT, "models", "scam_detector_svm", "model.joblib")
BERT_DIR = os.path.join(ROOT, "models", "scam_detector")


def build_svm():
    features = FeatureUnion([
        # Whole words and word pairs ("click here", "you won").
        ("word", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2)),
        # Character chunks catch obfuscation like "fr33", "c1ick", "w!n".
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2)),
    ])
    # Calibration turns SVM margins into real probabilities for the app's confidence %.
    svm = CalibratedClassifierCV(LinearSVC(C=1.0, class_weight="balanced", random_state=SEED), cv=5)
    return Pipeline([("features", features), ("clf", svm)])


def metrics(y_true, y_pred):
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred),
        "recall": recall_score(y_true, y_pred),
        "f1": f1_score(y_true, y_pred),
    }


def report(name, y_true, y_pred, ms_per_msg):
    print(f"\n=== {name} ===")
    print(classification_report(y_true, y_pred, target_names=["safe", "scam"], digits=4))
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    print(f"Missed scams (false negatives): {fn}   False alarms (false positives): {fp}")
    print(f"Inference: {ms_per_msg:.2f} ms / message")


def predict_bert(texts, batch_size=32):
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(BERT_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(BERT_DIR)
    model.eval()
    preds = []
    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            batch = tokenizer(texts[i:i + batch_size], return_tensors="pt",
                              truncation=True, padding=True, max_length=128)
            preds.extend(model(**batch).logits.argmax(dim=-1).tolist())
    return np.array(preds)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", default=DEFAULT_DATA, help="CSV with 'text' and 'label' columns")
    parser.add_argument("--skip-bert", action="store_true", help="don't evaluate DistilBERT")
    args = parser.parse_args()

    train_df, test_df = load_and_split_csv(args.data)
    train_df["text"] = train_df["text"].astype(str)
    test_df["text"] = test_df["text"].astype(str)
    X_test, y_test = test_df["text"].tolist(), test_df["label"].to_numpy()
    print(f"Train: {len(train_df)}  Test: {len(test_df)}  (seed={SEED})")

    # ---- SVM ----
    model = build_svm()
    t0 = time.perf_counter()
    model.fit(train_df["text"], train_df["label"])
    print(f"SVM trained in {time.perf_counter() - t0:.1f}s")

    t0 = time.perf_counter()
    svm_pred = model.predict(X_test)
    svm_ms = (time.perf_counter() - t0) * 1000 / len(X_test)
    report("TF-IDF + Linear SVM", y_test, svm_pred, svm_ms)

    os.makedirs(os.path.dirname(SVM_OUT), exist_ok=True)
    joblib.dump(model, SVM_OUT)
    print(f"Saved SVM to {SVM_OUT}")

    # ---- DistilBERT on the same test set ----
    results = {"SVM": metrics(y_test, svm_pred)}
    if not args.skip_bert:
        if not os.path.exists(os.path.join(BERT_DIR, "config.json")):
            print(f"\nNo DistilBERT model at {BERT_DIR}; skipping comparison.")
        else:
            print("\nRunning DistilBERT on the test set (this can take a minute on CPU)...")
            t0 = time.perf_counter()
            bert_pred = predict_bert(X_test)
            bert_ms = (time.perf_counter() - t0) * 1000 / len(X_test)
            report("DistilBERT", y_test, bert_pred, bert_ms)
            results["DistilBERT"] = metrics(y_test, bert_pred)

    # ---- Side-by-side ----
    print("\n=== Comparison (scam = positive class) ===")
    print(f"{'model':<12}" + "".join(f"{k:>11}" for k in ["accuracy", "precision", "recall", "f1"]))
    for name, m in results.items():
        print(f"{name:<12}" + "".join(f"{v:>11.4f}" for v in m.values()))


if __name__ == "__main__":
    main()
