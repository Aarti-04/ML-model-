import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split,cross_val_score
from sklearn.metrics import accuracy_score, classification_report
import pickle
from sklearn import svm
from imblearn.over_sampling import RandomOverSampler
from imblearn.under_sampling import RandomUnderSampler
import numpy as np

def train_model():
    #load dataset
    data = pd.read_csv('SMSSpamCollection', sep='\t', names=['label', 'message'])
     # Feature extraction
    print(data.head(100))
    count_vectorizer = CountVectorizer(stop_words='english')
    
    x = count_vectorizer.fit_transform(data['message'])
    print(x)

    y = data['label']
    # print(X)


    #  # Split dataset into training and testing sets

    X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)
    # #   # Train the model
    clf = MultinomialNB(alpha=0.5)
    # clf1 = svm.SVC(C=1.0, kernel='linear')  # Example for SVM with linear kernel
    clf.fit(X_train, y_train)

    # # Evaluate the model
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print("Accuracy:", accuracy)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    # cv_scores = cross_val_score(clf, x, y, cv=5, scoring='accuracy')
    # print("\nCross-Validation Scores:")
    # print(cv_scores)
    # print("Mean Accuracy:", np.mean(cv_scores))
    # Handling Imbalanced Data
    # oversampler = RandomOverSampler(sampling_strategy='minority')
    # undersampler = RandomUnderSampler(sampling_strategy='majority')
    # X_resampled, y_resampled = oversampler.fit_resample(x, y)
    # X_resampled, y_resampled = undersampler.fit_resample(X_resampled, y_resampled)

    # # Save the model and vectorizer
    # clf.fit(X_resampled, y_resampled)

    # Evaluate the model
    # y_pred = clf.predict(X_resampled)
    # accuracy = accuracy_score(y_resampled, y_pred)
    # print("accuracy score",accuracy)
    with open('spam_detector_model.pkl', 'wb') as model_file:
        pickle.dump(clf, model_file)
    with open('count_vectorizer.pkl', 'wb') as vectorizer_file:
        pickle.dump(count_vectorizer, vectorizer_file)

if __name__ == "__main__":
        train_model()