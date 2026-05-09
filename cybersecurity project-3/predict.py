import joblib
import pandas as pd

def predict_emails(email_list):
    """
    Loads the trained model and predicts if the given emails are Phishing or Safe.
    """
    model_path = 'models/phishing_detector.pkl'
    
    try:
        model = joblib.load(model_path)
    except FileNotFoundError:
        print("[-] Model not found! Please train the model first by running 'python train_evaluate.py'.")
        return
        
    df = pd.DataFrame({'text': email_list})
    predictions = model.predict(df)
    probabilities = model.predict_proba(df)[:, 1] # Probability of being phishing
    
    print("\n--- Prediction Results ---")
    for email, pred, prob in zip(email_list, predictions, probabilities):
        label = "Phishing" if pred == 1 else "Safe"
        print(f"\nEmail: \"{email[:75]}...\"")
        print(f"Prediction: {label} (Phishing Probability: {prob:.2f})")
    print("\n--------------------------")

if __name__ == "__main__":
    sample_emails = [
        "URGENT: Your bank account has been suspended. Please verify your identity by clicking this link: http://secure-update-bank.com/login",
        "Hi Team, just a reminder that we have a meeting scheduled for tomorrow at 10 AM in the main conference room.",
        "Security Alert! Unusual sign-in activity detected. Update your password immediately here: http://bit.ly/hax0r",
        "Hey, are we still on for lunch later? Let me know!",
        "Action Required: Your password expires today. Click to confirm your credentials."
    ]
    
    print("[*] Running predictions on sample emails...")
    predict_emails(sample_emails)
