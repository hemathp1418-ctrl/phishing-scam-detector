"""Train the scam text model and save it to models/scam_model.joblib.

Run:  python train.py
"""

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from scamdetector.model import build_pipeline, preprocess, save_model

df = pd.read_csv("data/messages.csv")
df["clean"] = df["text"].map(preprocess)
print(f"Loaded {len(df)} messages ({df['label'].sum()} scam, {(df['label'] == 0).sum()} legit)")

X_train, X_test, y_train, y_test = train_test_split(
    df["clean"], df["label"], test_size=0.2, random_state=42, stratify=df["label"])

pipe = build_pipeline()
pipe.fit(X_train, y_train)

pred = pipe.predict(X_test)
print("\nResults on held-out test set:")
print(classification_report(y_test, pred, target_names=["legit", "scam"]))
print("Confusion matrix [rows=true, cols=predicted]:\n", confusion_matrix(y_test, pred))

# Final model: retrain on ALL data before saving
pipe.fit(df["clean"], df["label"])
save_model(pipe)
print("\nSaved model to models/scam_model.joblib")
