# Phishing Email Detection Model

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.0%2B-orange)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

A professional Machine Learning project that classifies emails as either **Phishing** or **Safe** using Natural Language Processing (NLP) and Scikit-learn.

This project was built to demonstrate feature extraction, data preprocessing, and model pipeline building for cybersecurity and spam detection applications.

## 🎯 Key Features
- **Custom Feature Extraction**: Automatically extracts and counts suspicious URLs and keywords (e.g., "urgent", "password", "verify") from email bodies.
- **NLP with TF-IDF**: Uses Term Frequency-Inverse Document Frequency to vectorize the textual content of emails.
- **Scikit-learn Pipeline**: Integrates custom feature extractors and TF-IDF into a seamless `ColumnTransformer` and `FeatureUnion` architecture.
- **Random Forest Classifier**: Utilizes a robust ensemble method for highly accurate classification.
- **Evaluation & Visualization**: Outputs precision, recall, f1-score, and generates a visual Confusion Matrix.

---

## 📁 Project Structure

```text
phishing_detector/
│
├── data/                      # Directory for the datasets
│   └── emails.csv             # Generated dataset
│
├── models/                    # Directory for saved trained models
│   └── phishing_detector.pkl  # Serialized Scikit-learn model
│
├── src/                       # Source code modules
│   ├── __init__.py
│   ├── features.py            # Custom URL & Keyword extractors
│   └── model.py               # ML Pipeline and architecture definition
│
├── data_generator.py          # Script to generate a synthetic testing dataset
├── train_evaluate.py          # Script to train the model and output metrics
├── predict.py                 # Script to test the trained model on new emails
├── requirements.txt           # Project dependencies
└── README.md                  # This documentation file
```

---

## 🚀 Getting Started

### 1. Install Dependencies
Make sure you have Python installed. Then run:
```bash
pip install -r requirements.txt
```

### 2. Generate the Dataset
Since real phishing datasets often contain sensitive information, this project includes a synthetic data generator to get you started immediately.
```bash
python data_generator.py
```
*This will create a dataset of 2,500 sample emails in `data/emails.csv`.*

### 3. Train and Evaluate the Model
Train the Scikit-learn pipeline and see its performance.
```bash
python train_evaluate.py
```
**What this does:**
- Splits the dataset into 80% training and 20% testing sets.
- Trains the Random Forest pipeline.
- Prints the Model Accuracy and full Classification Report.
- Saves a heatmap image `confusion_matrix.png` in the root directory.
- Saves the trained model to `models/phishing_detector.pkl`.

### 4. Make Predictions (CLI)
Test the model against a set of sample strings (or add your own) to see how it performs in real-time!
```bash
python predict.py
```

### 5. Launch the Web App (New!)
Experience the model through a premium, glassmorphism-styled web interface.
```bash
python app.py
```
*Then open `http://127.0.0.1:5000` in your browser.*

---

## 🧠 How it Works (Under the Hood)

The core architecture revolves around the **Scikit-learn Pipeline**. 

1. **Text Column**: The raw email text is passed into the `ColumnTransformer`.
2. **Text Processing (`TfidfVectorizer`)**: The text is cleaned (stopwords removed) and vectorized based on word frequencies.
3. **Custom Processing (`FeatureUnion`)**: 
   - `URLFeatureExtractor`: Counts the exact number of HTTP/HTTPS links in the email.
   - `KeywordFeatureExtractor`: Scans for malicious keywords commonly found in phishing attempts.
4. **Classification (`RandomForestClassifier`)**: The synthesized features are fed into a Random Forest algorithm which learns the patterns distinguishing a safe email from a phishing email.

---

## 📊 Sample Output
```text
========================================
[+] Model Accuracy: 100.00%
========================================

Classification Report:
--------------------------------------------------
              precision    recall  f1-score   support

        Safe       1.00      1.00      1.00       302
    Phishing       1.00      1.00      1.00       198

    accuracy                           1.00       500
   macro avg       1.00      1.00      1.00       500
weighted avg       1.00      1.00      1.00       500
--------------------------------------------------
[+] Confusion matrix saved to confusion_matrix.png
```
*(Note: Because the `data_generator.py` uses templates, the model will achieve near-perfect accuracy. For a real-world challenge, replace `emails.csv` with a Kaggle dataset like the "SpamAssassin Public Corpus".)*

## 📜 License
This project is open-source and available under the MIT License. Feel free to use it for your internships, portfolio, or personal learning!
