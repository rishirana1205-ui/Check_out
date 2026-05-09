from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from src.features import URLFeatureExtractor, KeywordFeatureExtractor

def build_model():
    """
    Builds the Scikit-learn machine learning pipeline.
    It processes text via TF-IDF and extracts custom features (URL counts, keywords).
    """
    
    # Text processing: TF-IDF
    text_transformer = Pipeline(steps=[
        ('tfidf', TfidfVectorizer(max_features=3000, stop_words='english', ngram_range=(1, 2)))
    ])
    
    # Custom feature processing
    custom_features = FeatureUnion([
        ('urls', URLFeatureExtractor()),
        ('keywords', KeywordFeatureExtractor())
    ])
    
    # Column transformer to apply different transformations to the text column
    preprocessor = ColumnTransformer(
        transformers=[
            ('text_tfidf', text_transformer, 'text'),
            ('custom_features', custom_features, 'text')
        ],
        remainder='drop'
    )
    
    # Final Pipeline with a Classifier
    model = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced'))
    ])
    
    return model
