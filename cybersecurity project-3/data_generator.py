import pandas as pd
import random
import os

SAFE_TEMPLATES = [
    "Hi {name}, let's schedule a meeting for {day} at {time}.",
    "Attached is the report for Q{quarter}. Let me know if you need any changes.",
    "Are we still going to lunch? I was thinking we could go to {place}.",
    "The project deadline has been extended to {day}. Keep up the good work!",
    "Hey! Just checking in to see how you're doing. Call me when you can.",
    "Please review the attached pull request when you have a moment.",
    "Can you send me the presentation slides from yesterday?",
    "Thanks for your help with the bug fix! It works perfectly now.",
    "Reminder: Team building event next {day}.",
    "I will be out of office starting {day} and returning on {day}.",
    "Hi team, just a quick update on the project status.",
    "Can we reschedule our call to {time}? I have a conflict."
]

PHISHING_TEMPLATES = [
    "URGENT: Your {service} account will be suspended in 24 hours. Click here to verify your identity: {url}",
    "Security Alert: We detected an unusual login to your {service} account. Please update your password immediately at {url}",
    "Dear Customer, your bank account access is restricted. Verify your information here: {url}",
    "You have won a $1000 gift card! Claim your prize now by visiting {url}",
    "Important update regarding your account security. Please login to confirm your details: {url}",
    "Invoice #{num} is due. Please review the attached document and submit payment via {url}",
    "Your package could not be delivered. Please update your shipping address here: {url}",
    "Action Required: Your password expires today. Change it now at {url}",
    "We noticed suspicious activity on your credit card. Confirm your recent transactions at {url}",
    "IT Helpdesk: We are migrating email servers. Please validate your inbox at {url} to avoid losing emails."
]

SERVICES = ["PayPal", "Bank of America", "Chase", "Apple", "Google", "Amazon", "Microsoft", "Netflix", "Wells Fargo"]
NAMES = ["John", "Sarah", "Mike", "Emily", "David", "Jessica", "Alex", "Chris", "Taylor", "Jordan"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
TIMES = ["10 AM", "1 PM", "3 PM", "4:30 PM", "9:00 AM"]
PLACES = ["Chipotle", "the cafe", "Panera", "that new sushi place", "Starbucks"]
URLS = ["http://secure-login-verify.com", "http://bit.ly/123xyz", "http://update-your-billing.net", "http://account-recovery-service.org", "http://confirm-identity-now.com"]

def generate_synthetic_data(num_samples=2500):
    data = []
    
    for _ in range(num_samples):
        # 40% Phishing, 60% Safe split for a more realistic imbalance (though still high)
        is_phishing = random.random() < 0.40 
        
        if is_phishing:
            template = random.choice(PHISHING_TEMPLATES)
            text = template.format(
                service=random.choice(SERVICES),
                url=random.choice(URLS),
                num=random.randint(1000, 9999)
            )
            label = 1
        else:
            template = random.choice(SAFE_TEMPLATES)
            text = template.format(
                name=random.choice(NAMES),
                day=random.choice(DAYS),
                time=random.choice(TIMES),
                quarter=random.randint(1, 4),
                place=random.choice(PLACES)
            )
            label = 0
            
        data.append({'text': text, 'label': label})
        
    return pd.DataFrame(data)

if __name__ == "__main__":
    print("[*] Generating synthetic dataset...")
    df = generate_synthetic_data(2500)
    
    os.makedirs('data', exist_ok=True)
    df.to_csv('data/emails.csv', index=False)
    print(f"[+] Dataset generated successfully with {len(df)} samples: data/emails.csv")
    print(f"    - Safe emails (0): {len(df[df['label'] == 0])}")
    print(f"    - Phishing emails (1): {len(df[df['label'] == 1])}")
