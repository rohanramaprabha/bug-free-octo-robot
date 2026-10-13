"""
PrivacyVault AI - Machine Learning Privacy Risk Classifier
Uses scikit-learn TF-IDF Vectorizer and Multinomial Naive Bayes / Logistic Regression
to classify full document confidentiality into 5 distinct categories.
"""

import os
from pathlib import Path
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from config.settings import Config

MODEL_FILE = Config.DATA_FOLDER / "privacy_ml_model.joblib"

# Diverse training corpus across 5 privacy categories
TRAINING_DATA = [
    # 1. PII
    ("Employee Directory Name John Doe Email john.doe@work.com Phone 555-0199 Address 123 Elm Street City Chicago SSN 123-45-6789 Date of Birth 1985-04-12", "PII"),
    ("Patient intake medical history patient name Jane Smith diagnosis allergy guardian contact phone 9876543210 Aadhaar 9876 5432 1098 emergency contact", "PII"),
    ("Customer registration profile username alex_92 email alex@mail.com mobile +91 98450 12345 residential postal address Bangalore Karnataka", "PII"),
    ("Student enrollment record applicant name Sarah Connor passport number N12345678 home address postal code next of kin telephone", "PII"),
    ("User personal identity demographic survey respondents full name contact email phone number home street address", "PII"),
    
    # 2. Financial
    ("Payroll report employee salary compensation CTC annual package monthly gross deduction bank account IBAN routing transit direct deposit", "Financial"),
    ("Credit card transaction billing account number 4111222233334444 expiration date CVV security code merchant invoice total balance due", "Financial"),
    ("Quarterly revenue bank statement wire transfer incoming debit credit balance ledger account holder swift code", "Financial"),
    ("Tax return form 1040 gross income taxable compensation deductions withholding refund bank account routing number", "Financial"),
    ("Invoice statement payment terms net 30 payment method visa mastercard total amount payable remitted", "Financial"),

    # 3. Authentication Secrets
    ("aws_access_key_id = AKIAIOSFODNN7EXAMPLE aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY region = us-east-1", "Authentication Secrets"),
    ("export GITHUB_TOKEN=ghp_ABC1234567890abcdefghijklmnopqrstuv export SLACK_BOT_TOKEN=xoxb-123456789-987654321-abcdef", "Authentication Secrets"),
    ("-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEA0Y9lK... -----END RSA PRIVATE KEY----- database_password = SuperSecretPass123!", "Authentication Secrets"),
    ("JWT Bearer token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotShareThisSignature client_secret production", "Authentication Secrets"),
    ("API_KEY=prod_live_9988776655443322 auth_secret=xoxp-99887766 admin_credentials password_hash root_access", "Authentication Secrets"),

    # 4. Confidential Business
    ("STRICTLY CONFIDENTIAL Project Titan Merger and Acquisition targets valuation non-disclosure agreement trade secret board of directors only", "Confidential Business"),
    ("PROPRIETARY AND RESTRICTED internal patent filing draft proprietary chemical formulation manufacturing process do not distribute", "Confidential Business"),
    ("Executive compensation committee minutes acquisition discussions tender offer privileged legal advice under attorney-client privilege", "Confidential Business"),
    ("Strategic roadmap 2027 commercial pricing algorithms competitive intelligence confidential business evaluation NDA covered", "Confidential Business"),
    ("Strictly Private commercial contract vendor terms intellectual property assignment dispute arbitration clause trade secrets", "Confidential Business"),

    # 5. Public / Low Sensitivity
    ("Welcome to our open source project documentation! Read our public getting started guide, license terms, and developer tutorials.", "Public / Low Sensitivity"),
    ("Company news and press release: We are excited to announce our new community software release available for free download.", "Public / Low Sensitivity"),
    ("Standard website footer terms of use cookie policy general privacy disclaimer frequently asked questions public forum", "Public / Low Sensitivity"),
    ("Software user guide: Chapter 1 Installing application requirements on Windows and macOS. Click next to continue installation.", "Public / Low Sensitivity"),
    ("Weather forecast public information report for upcoming weekend sports event schedule community picnic details", "Public / Low Sensitivity")
]


class PrivacyMLClassifier:
    """Document sensitivity classifier utilizing Scikit-learn Pipeline with TF-IDF & MultinomialNB."""
    
    def __init__(self):
        self.model: Pipeline = None
        self._ensure_trained_model()
        
    def _train(self):
        """Train classifier pipeline and save model to disk."""
        texts, labels = zip(*TRAINING_DATA)
        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=1500, stop_words="english")),
            ("clf", MultinomialNB(alpha=0.1))
        ])
        pipeline.fit(texts, labels)
        self.model = pipeline
        
        # Save model
        Config.ensure_directories()
        joblib.dump(pipeline, MODEL_FILE)
        
    def _ensure_trained_model(self):
        """Load pre-trained model or train new one."""
        if MODEL_FILE.exists():
            try:
                self.model = joblib.load(MODEL_FILE)
                return
            except Exception:
                pass
        self._train()
        
    def predict(self, text: str) -> dict:
        """
        Predict document privacy class and confidence score.
        Returns: {
            "predicted_category": str,
            "confidence": float,
            "top_keywords": list[str]
        }
        """
        clean_text = text.strip()
        if not clean_text or len(clean_text) < 10:
            return {
                "predicted_category": "Public / Low Sensitivity",
                "confidence": 0.50,
                "top_keywords": []
            }
            
        probas = self.model.predict_proba([clean_text])[0]
        classes = self.model.classes_
        best_idx = probas.argmax()
        predicted_category = classes[best_idx]
        confidence = float(probas[best_idx])
        
        # Extract top TF-IDF feature keywords for transparency
        tfidf = self.model.named_steps["tfidf"]
        feature_names = tfidf.get_feature_names_out()
        tfidf_vec = tfidf.transform([clean_text]).toarray()[0]
        top_indices = tfidf_vec.argsort()[::-1][:5]
        top_keywords = [feature_names[i] for i in top_indices if tfidf_vec[i] > 0]
        
        return {
            "predicted_category": predicted_category,
            "confidence": round(confidence, 2),
            "top_keywords": top_keywords
        }


# Global singleton instance
_classifier_instance = None

def get_ml_classifier() -> PrivacyMLClassifier:
    """Retrieve or initialize singleton ML classifier."""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = PrivacyMLClassifier()
    return _classifier_instance
