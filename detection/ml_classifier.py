import os
import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)

MODEL_PATH = "models/prompt_classifier.joblib"


def train_classifier():
    data = pd.read_csv("dataset/prompts.csv")

    X = data["prompt"].astype(str)
    y = data["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer()),
        ("classifier", LogisticRegression(max_iter=1000))
    ])

    # Train using training data
    model.fit(X_train, y_train)

    # Evaluate using unseen test data
    predictions = model.predict(X_test)

    print("\n========== PROMPTSHIELD MODEL EVALUATION ==========")
    print(f"Accuracy:  {accuracy_score(y_test, predictions) * 100:.2f}%")
    print(f"Precision: {precision_score(y_test, predictions, average='macro', zero_division=0) * 100:.2f}%")
    print(f"Recall:    {recall_score(y_test, predictions, average='macro', zero_division=0) * 100:.2f}%")
    print(f"F1 Score:  {f1_score(y_test, predictions, average='macro', zero_division=0) * 100:.2f}%")

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        predictions,
        zero_division=0
    ))

    # Retrain on the complete dataset before saving
    model.fit(X, y)

    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    print(f"\nTrained model saved to: {MODEL_PATH}")
    print("===================================================\n")

    return model


def load_classifier():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)

    return train_classifier()


def predict_prompt(prompt, model):
    prediction = model.predict([prompt])[0]

    probability = model.predict_proba([prompt])[0]
    confidence = max(probability)

    return {
        "prediction": prediction,
        "confidence": round(float(confidence) * 100, 2)
    }


if __name__ == "__main__":
    train_classifier()