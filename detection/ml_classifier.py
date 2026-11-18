import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report


def train_classifier():
    data = pd.read_csv("dataset/prompts.csv")

    X = data["prompt"]
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

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("Model Training Completed!")
    print("Accuracy:", accuracy_score(y_test, predictions))
    print(classification_report(
        y_test,
        predictions,
        zero_division=0
    ))

    return model


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