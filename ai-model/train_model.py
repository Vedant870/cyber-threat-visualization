import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib


def main():
    data_path = "data/synthetic_threat_events.csv"
    df = pd.read_csv(data_path)

    X = df[
        [
            "failed_logins",
            "anomaly_score",
            "severity_score",
            "source_reputation",
            "data_exfiltration_mb",
            "geo_risk_score",
            "alert_count",
        ]
    ]
    y = df["threat_level"]

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    model = RandomForestClassifier(n_estimators=200, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print("Accuracy:", round(accuracy, 4))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    joblib.dump(
        {"model": model, "label_encoder": label_encoder}, "model.joblib"
    )


if __name__ == "__main__":
    main()
