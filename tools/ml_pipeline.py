import pandas as pd
import numpy as np
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "dns_exfiltration_dataset.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODELS_DIR, "dns_pipeline_model.joblib")
SCALER_PATH = os.path.join(MODELS_DIR, "dns_pipeline_scaler.joblib")

def load_and_validate_data():
    print("[*] Loading dataset...")
    df = pd.read_csv(DATA_PATH)
    
    print(f"[*] Initial Shape: {df.shape}")
    
    # 1. Missing Values
    if df.isnull().sum().any():
        print("[!] Dropping missing values.")
        df = df.dropna()
        
    # 2. Duplicates
    dupes = df.duplicated().sum()
    if dupes > 0:
        print(f"[!] Dropping {dupes} duplicates.")
        df = df.drop_duplicates()
        
    # 3. Class Balance
    print("[*] Class Distribution:")
    print(df['label'].value_counts(normalize=True) * 100)
    
    # 4. Drop irrelevant features
    if 'source_ip' in df.columns:
        print("[*] Dropping uninformative 'source_ip' column for structural ML training.")
        df = df.drop(columns=['source_ip'])
        
    return df

def feature_engineering(df):
    print("[*] Generating Advanced Features...")
    # Prevent division by zero
    df['length'] = df['length'].replace(0, 1)
    
    # Create new features
    df['entropy_to_length_ratio'] = df['entropy'] / df['length']
    df['high_entropy_flag'] = (df['entropy'] > 3.8).astype(int)
    # Heuristic complexity score
    df['domain_complexity'] = (df['length'] * df['entropy']) - (df['ngram_score'] * 10)
    
    return df

def train_evaluate_pipeline():
    df = load_and_validate_data()
    df = feature_engineering(df)
    
    # Define feature array
    X = df.drop(columns=['domain', 'label'])
    y = df['label']
    
    # Scale numerical features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Save Scaler
    joblib.dump(scaler, SCALER_PATH)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, stratify=y, random_state=42)
    
    print("[*] Training Pipeline Executing...")
    
    # Define models
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42),
        "Random Forest": RandomForestClassifier(random_state=42)
    }
    
    # Optional: Fast Hyperparameter tuning for Random Forest
    param_dist = {
        'n_estimators': [100, 200, 300],
        'max_depth': [None, 10, 20, 30],
        'min_samples_split': [2, 5, 10]
    }
    
    print("[*] Tuning Random Forest via RandomizedSearchCV...")
    rf_search = RandomizedSearchCV(RandomForestClassifier(random_state=42), param_distributions=param_dist, 
                                   n_iter=5, cv=3, scoring='f1', n_jobs=-1, random_state=42)
    rf_search.fit(X_train, y_train)
    
    best_model = rf_search.best_estimator_
    print(f"[*] Best Parameters: {rf_search.best_params_}")
    
    # Save Best Model
    joblib.dump(best_model, MODEL_PATH)
    
    # Evaluation
    print("\n" + "="*50)
    print("FINAL MODEL EVALUATION (RANDOM FOREST)")
    print("="*50)
    y_pred = best_model.predict(X_test)
    
    print(classification_report(y_test, y_pred))
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Malicious'], yticklabels=['Normal', 'Malicious'])
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.title('Confusion Matrix - DNS Exfiltration')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, 'confusion_matrix.png'))
    print(f"[*] Saved Confusion Matrix plot to confusion_matrix.png")
    
    # Explainability (Feature Importance)
    print("\nFEATURE IMPORTANCES:")
    importances = best_model.feature_importances_
    for feature, imp in sorted(zip(X.columns, importances), key=lambda x: x[1], reverse=True):
        print(f"  - {feature}: {imp*100:.2f}%")

def risk_engine(probability):
    """Categorizes risk based on 0-100 normalized score"""
    risk_score = probability * 100
    if risk_score >= 70:
        return "High", risk_score
    elif risk_score >= 30:
        return "Medium", risk_score
    else:
        return "Low", risk_score

def inference_pipeline(domain, entropy, length, ngram_score):
    """Live inference function simulating the backend prediction"""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        raise Exception("Model or scaler not found. Run training first.")
        
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    
    # Manual dynamic feature generation
    length = length if length > 0 else 1
    entropy_to_length_ratio = entropy / length
    high_entropy_flag = 1 if entropy > 3.8 else 0
    domain_complexity = (length * entropy) - (ngram_score * 10)
    
    feature_dict = {
        'entropy': entropy,
        'length': length,
        'ngram_score': ngram_score,
        'entropy_to_length_ratio': entropy_to_length_ratio,
        'high_entropy_flag': high_entropy_flag,
        'domain_complexity': domain_complexity
    }
    
    # Prepare array
    features_df = pd.DataFrame([feature_dict])
    X_scaled = scaler.transform(features_df)
    
    # Predict
    pred = model.predict(X_scaled)[0]
    prob = model.predict_proba(X_scaled)[0][1] # Probability of being class 1 (Malicious)
    
    severity, risk_score = risk_engine(prob)
    
    # Explanation
    reasons = []
    if high_entropy_flag: reasons.append(f"High entropy ({entropy:.2f}) indicates encrypted or packed data.")
    if length > 22: reasons.append(f"Excessive domain length ({length} chars) typical of tunneling.")
    if ngram_score == 0: reasons.append("Zero linguistic n-gram match; likely Domain Generation Algorithm (DGA).")
    
    if not reasons and pred == 1:
        reasons.append("Multi-dimensional tree nodes mapped to known malicious feature clusters.")
        
    return {
        "Domain": domain,
        "Prediction": "Malicious" if pred == 1 else "Normal",
        "Probability": f"{prob*100:.1f}%",
        "Risk_Score": f"{risk_score:.1f}/100",
        "Severity": severity,
        "Explanation": " | ".join(reasons) if pred == 1 else "Normal traffic structures observed."
    }

if __name__ == "__main__":
    # 1. Run the Training Pipeline
    train_evaluate_pipeline()
    
    # 2. Test Edge Cases Inference
    print("\n" + "="*50)
    print("INFERENCE EDGE CASE TESTING")
    print("="*50)
    
    tests = [
        {"domain": "google.com", "entropy": 2.6, "length": 10, "ngram_score": 0.05},
        {"domain": "ij90kl.tunnel-c2.malicious.net", "entropy": 4.1, "length": 30, "ngram_score": 0.00},
        {"domain": "randomstring123456.com", "entropy": 3.9, "length": 22, "ngram_score": 0.01}
    ]
    
    for t in tests:
        res = inference_pipeline(t['domain'], t['entropy'], t['length'], t['ngram_score'])
        print(f"\nTarget: {res['Domain']}")
        print(f" -> Result: {res['Prediction']} ({res['Severity']} Risk: {res['Risk_Score']})")
        print(f" -> Prob:   {res['Probability']}")
        print(f" -> Note:   {res['Explanation']}")
