"""Train a lightweight message phishing classifier on synthetic demo data."""
from pathlib import Path
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "message_model.joblib"

def demo_dataset() -> pd.DataFrame:
    """Return synthetic data to make the demo run; not suitable for validation."""
    benign = [
        "Your library book is due next Tuesday. Renew it online if needed.",
        "Hi team, the project meeting has moved to 2 pm in the main room.",
        "Thanks for your order. Your receipt is available in your account.",
        "The monthly newsletter is ready. Read the latest community updates.",
        "Please review the attached agenda before our planning session.",
        "Your package will arrive tomorrow. Track delivery from our website.",
        "We received your support request and will reply within two days.",
        "Your appointment is confirmed for Friday at 10 am.",
        "The class notes have been posted to the student portal.",
        "A sign-in code was requested. If this was you, enter it in the app.",
        "Your payment was processed. Contact customer support with questions.",
        "The shared document was updated by your colleague this morning.",
    ]
    phishing = [
        "Immediate action required: verify your account now to avoid suspension.",
        "Your mailbox will be suspended today. Click here to restore access.",
        "We detected unusual activity. Confirm your password immediately.",
        "Your bank account is locked. Verify account details using this link.",
        "Final warning: claim your prize now by entering your card information.",
        "Payroll failed. Open the link and sign in to release your payment.",
        "Your subscription expires today. Update billing details immediately.",
        "Unusual login detected. Reply with your password to secure your account.",
        "The tax refund is waiting. Submit your personal information now.",
        "Action needed: verify your identity or your account will be closed.",
        "Your cloud storage is full. Login here to prevent data deletion.",
        "You won a gift card. Click now and confirm your bank details.",
    ]
    return pd.DataFrame({"text": benign + phishing, "label": [0] * len(benign) + [1] * len(phishing)})

def train(data: pd.DataFrame | None = None, output_path: Path = MODEL_PATH) -> None:
    """Train, report holdout metrics, and save the fitted scikit-learn pipeline."""
    data = demo_dataset() if data is None else data
    if not {"text", "label"}.issubset(data.columns):
        raise ValueError("Input data must contain 'text' and 'label' columns.")
    data = data.dropna(subset=["text", "label"])
    labels = data["label"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(
        data["text"].astype(str), labels, test_size=0.25, random_state=42, stratify=labels)
    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, strip_accents="unicode")),
        ("classifier", MultinomialNB(alpha=0.5)),
    ])
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    print(f"Holdout accuracy: {accuracy_score(y_test, predictions):.3f}")
    print("Confusion matrix (rows=true, columns=predicted; labels 0,1):")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))
    print(classification_report(y_test, predictions, labels=[0, 1],
                               target_names=["legitimate", "phishing"], zero_division=0))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)
    print(f"Saved model to {output_path}")
    print("Synthetic demo metrics are not evidence of real-world performance.")

if __name__ == "__main__":
    train()
