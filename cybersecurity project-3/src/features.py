import re
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extracts the count of URLs in the email text."""
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        # X is expected to be a pandas Series of strings
        url_counts = X.apply(lambda text: len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(text))))
        return pd.DataFrame({'url_count': url_counts})

class KeywordFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extracts the count of suspicious keywords often found in phishing emails."""
    def __init__(self):
        self.keywords = [
            'urgent', 'password', 'verify', 'account', 'bank', 
            'login', 'update', 'suspended', 'security', 'alert',
            'confirm', 'restricted', 'action required'
        ]

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        keyword_counts = X.apply(
            lambda text: sum(str(text).lower().count(k) for k in self.keywords)
        )
        return pd.DataFrame({'suspicious_keyword_count': keyword_counts})
