from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import os

app = Flask(__name__)

# Load the trained model
MODEL_PATH = 'models/phishing_detector.pkl'
try:
    model = joblib.load(MODEL_PATH)
    print("[+] Model loaded successfully for Web App.")
except Exception as e:
    print(f"[-] Error loading model: {e}. Please run train_evaluate.py first.")
    model = None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if not model:
        return jsonify({'error': 'Model not loaded on the server.'}), 500
        
    data = request.json
    email_text = data.get('text', '')
    
    if not email_text:
        return jsonify({'error': 'No text provided'}), 400
        
    df = pd.DataFrame({'text': [email_text]})
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0][1] # Probability of being phishing
    
    result = {
        'prediction': "Phishing" if prediction == 1 else "Safe",
        'probability': float(probability)
    }
    
    return jsonify(result)

if __name__ == '__main__':
    print("[*] Starting AI Phishing Detector Server...")
    app.run(debug=True, port=5000)
