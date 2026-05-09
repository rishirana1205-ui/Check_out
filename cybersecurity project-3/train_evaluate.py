import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

from src.model import build_model

def plot_confusion_matrix(y_true, y_pred, output_path="confusion_matrix.png"):
    """Generates and saves the confusion matrix plot."""
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Safe', 'Phishing'], 
                yticklabels=['Safe', 'Phishing'])
    plt.title('Phishing Detection Confusion Matrix')
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(output_path)
    print(f"[+] Confusion matrix saved to {output_path}")

def main():
    data_path = 'data/emails.csv'
    
    if not os.path.exists(data_path):
        print("[-] Dataset not found! Please run 'python data_generator.py' first.")
        return

    print("[*] Loading dataset...")
    df = pd.read_csv(data_path)
    
    if 'text' not in df.columns or 'label' not in df.columns:
        print("[-] Dataset must contain 'text' and 'label' columns.")
        return
        
    X = df[['text']]
    y = df['label']
    
    print("[*] Splitting data into train and test sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("[*] Building the model pipeline...")
    model = build_model()
    
    print("[*] Training the model (this might take a moment)...")
    model.fit(X_train, y_train)
    
    print("[*] Evaluating the model...")
    y_pred = model.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    print(f"\n========================================")
    print(f"[+] Model Accuracy: {acc * 100:.2f}%")
    print(f"========================================\n")
    
    print("Classification Report:")
    print("-" * 50)
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))
    print("-" * 50)
    
    # Plot confusion matrix
    plot_confusion_matrix(y_test, y_pred)
    
    # Save the model
    os.makedirs('models', exist_ok=True)
    model_path = 'models/phishing_detector.pkl'
    joblib.dump(model, model_path)
    print(f"[+] Model saved successfully to {model_path}")

if __name__ == "__main__":
    main()
