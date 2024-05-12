from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.views import APIView,Response,status
import json
import re
import pickle
import os
# Create your views here.

class Predict(APIView):
  def preprocess_email_body(self,body):
    # print("pre body",body)
    # Remove URLs
    body = re.sub(r'http[s]?://\S+', '', body)
    # Remove email addresses
    body = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '', body)
    # Remove special characters and digits
    body = re.sub(r'[^a-zA-Z\s]', '', body)
    # Convert to lowercase
    body = body.lower()
    # print("processed body",body)
    return body
  def post(self,request):
    data = request.body
    # print(data)
    # Decode the bytes to a string
    message_data = data.decode('utf-8')
    message=json.loads(message_data)
    # print("message",message["message"])
    #preprocess data
    # return Response("hello")
    cleaned_body = self.preprocess_email_body(message["message"])
    # Load the saved model and vectorizer     
    model_path = os.path.join(os.path.dirname(__file__), 'spam_detector_model.pkl')
    vectorizer_path = os.path.join(os.path.dirname(__file__), 'count_vectorizer.pkl')
    with open(model_path, 'rb') as model_file:
        clf = pickle.load(model_file)
        # print(clf)
    with open(vectorizer_path, 'rb') as vectorizer_file:
        count_vectorizer = pickle.load(vectorizer_file)
        # print(count_vectorizer)
    message_vector = count_vectorizer.transform([cleaned_body])
      # Make a prediction
    prediction = clf.predict(message_vector)
    return Response({'prediction': prediction[0]},status=status.HTTP_200_OK)

class Train(APIView):
  def post(self,request):
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
    clf = MultinomialNB()
    # clf=svm.SVC()
    clf.fit(X_train, y_train)

    # # Evaluate the model
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print("Accuracy:", accuracy)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    # # Save the model and vectorizer

    with open('spam_detector_model.pkl', 'wb') as model_file:
        pickle.dump(clf, model_file)
    with open('count_vectorizer.pkl', 'wb') as vectorizer_file:
        pickle.dump(count_vectorizer, vectorizer_file)
      
