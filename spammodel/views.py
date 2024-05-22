from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.views import APIView,Response,status
import json
import re
import pickle
import os
import pandas as pd
import matplotlib.pyplot as plt
import cloudinary
from cloudinary.uploader import upload
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split,cross_val_score
from sklearn.metrics import accuracy_score, classification_report
import pickle
from sklearn import svm
from detector.models import EmailMessageModel
# from imblearn.over_samplin
# g import RandomOverSampler
# from imblearn.under_sampling import RandomUnderSampler
import numpy as np
from django.conf import settings
from .utils import is_html,preprocess_email_body

from dotenv import load_dotenv
import csv
from rest_framework.permissions import IsAuthenticated,IsAdminUser,AllowAny
load_dotenv()
# Create your views here.


class Feedback(APIView):
    permission_classes=[IsAuthenticated]
    def post(self, request):
        message_id = request.data.get('message_id')
        correct_label = request.data.get('spam_label')
        email_message = EmailMessageModel.objects.get(id=message_id)
        email_body = preprocess_email_body(email_message.body)

        # Save feedback to CSV
        feedback_path = os.path.join(settings.BASE_DIR, 'spammodel', 'user_feedback.csv')
        new_feedback = pd.DataFrame({
            'label': [correct_label],
            'message': [email_body]
        })
        
        # Append feedback data to CSV file
        if os.path.exists(feedback_path):
            new_feedback.to_csv(feedback_path, mode='a', header=False, index=False, sep='\t')
        else:
            new_feedback.to_csv(feedback_path, mode='w', header=True, index=False, sep='\t')

        # the existing model and vectorizer
        model_save_path = os.path.join(settings.BASE_DIR, 'spammodel', 'spam_detector_model.pkl')
        vectorizer_save_path = os.path.join(settings.BASE_DIR, 'spammodel', 'count_vectorizer.pkl')
        with open(model_save_path, 'rb') as model_file:
            clf = pickle.load(model_file)
        with open(vectorizer_save_path, 'rb') as vectorizer_file:
            count_vectorizer = pickle.load(vectorizer_file)
        # return Response("trainned")
        # original training data
        file_path = os.path.join(settings.BASE_DIR, 'spammodel', 'SMSSpamCollection')
        data = pd.read_csv(file_path, sep='\t', names=['label', 'message'])
        # feedback data
        feedback_data = pd.read_csv(feedback_path, sep='\t', names=['label', 'message'])
        feedback_data.drop_duplicates(inplace=True)
        print(feedback_data.head())
        # Combine original data with feedback data
        data = pd.concat([data, feedback_data], ignore_index=True)
        
        # Feature extraction using the existing vectorizer
        # print(count_vectorizer)
        data.dropna(subset=['message'], inplace=True)
        X = count_vectorizer.transform(data['message'])
        y = data['label']
        
        # Split dataset into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Retrain the model with combined data
        clf.fit(X_train, y_train)

        # Evaluate the retrained model
        y_pred = clf.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        classification_model_report = classification_report(y_test, y_pred)

        print("Model retrained with feedback.")
        print("Accuracy:", accuracy)
        print("Classification report:\n", classification_model_report)

        # Save the updated model and vectorizer
        with open(model_save_path, 'wb') as model_file:
            print("Saving updated spam_detector_model.pkl")
            pickle.dump(clf, model_file)

        with open(vectorizer_save_path, 'wb') as vectorizer_file:
            print("Saving updated count_vectorizer.pkl")
            pickle.dump(count_vectorizer, vectorizer_file)

        return Response({
            "success": "Feedback received and model retrained",
            "accuracy": accuracy,
            "classification_report": classification_model_report,
            "graph_url": ""
        }, status=status.HTTP_201_CREATED)

class Predict(APIView):
#   permission_classes=[IsAuthenticated]
  def post(self,request):
    # data = request.body.decode('utf-8')
    # print(data)
    # Decode the bytes to a string
    # message_data=json.loads(data)
    # print(message_data)
    # message_body=message_data["body"]
    # return Response("predict")
    #preprocess data
    message_body=request.data.get('body')
    if(message_body!=''):
      print("message got")
    else:
       print("body is none")
    cleaned_body = preprocess_email_body(message_body)
    # print("cleaned_body",cleaned_body)
    # return Response({'is_spam': False},status=status.HTTP_200_OK)

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
    print("prediction",prediction[0])
    if(prediction[0]=="spam"):
        return Response({"is_spam": True},status=status.HTTP_200_OK)
    return Response({'is_spam': False},status=status.HTTP_200_OK)


class Train(APIView):
    def model_train_with_different_file(self):
        pass
        # file_path= os.path.join(settings.BASE_DIR, 'spammodel', 'spam_ham_dataset.csv')
        # data = pd.read_csv(file_path)
        # data = data[['label', 'message']]
        # dataset_paths = [
        #     os.path.join(settings.BASE_DIR, 'spammodel', 'SMSSpamCollection'),
        #     os.path.join(settings.BASE_DIR, 'spammodel', 'spam_ham_dataset.csv')
        #     # Add more paths as needed
        # ]
        # print(dataset_paths)
        
        # # Load and preprocess datasets
        # data_list = []
        # for path in dataset_paths:
        #     if 'SMSSpamCollection' in path:
        #         # First CSV file with tab-separated values
        #         data = pd.read_csv(path, sep='\t', names=['label', 'message'])
        #     elif 'spam_ham_dataset.csv' in path:
        #         # Second CSV file with additional columns
        #         data = pd.read_csv(path)
        #         data = data[['label', 'message']]  # Select only relevant columns
            
        #     data_list.append(data)
        
        # # Combine datasets
        # data = pd.concat(data_list, ignore_index=True)

        # # # Feature extraction
        # print(data.head(10))
    def post(self,request):
    
        file_path = os.path.join(settings.BASE_DIR, 'spammodel', 'SMSSpamCollection')
        data = pd.read_csv(file_path, sep='\t', names=['label', 'message'])
        # Feature extraction
        print(data.head(100))
        # feedback_path = os.path.join(settings.BASE_DIR, 'spammodel', 'user_feedback.csv')
        # # feedback_path=""
        # if os.path.exists(feedback_path):
        #     feedback_data = pd.read_csv(feedback_path,sep='\t', names=['label', 'message'])
        #     print("feedback_data",feedback_data)
        #     # Combine original data with feedback
        #     data = pd.concat([data, feedback_data], ignore_index=True)
        #     print("data",data)
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
        classification_model_report=classification_report(y_test, y_pred)
        print(classification_model_report)
        plt.figure(figsize=(8, 6))
        plt.plot([1, 2], [accuracy, accuracy], marker='o', linestyle='-', color='b', label='Accuracy')
        plt.title('Model Performance')
        plt.xlabel('Iterations')
        plt.ylabel('Accuracy')
        plt.xticks([1, 2], ['Training', 'Testing'])
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        # plt.show()
        # Save the graph
        # graph_temp_file = os.path.join(settings.BASE_DIR, 'spammodel', 'model_performance.png')
        # plt.savefig(graph_temp_file)
        # plt.close()
        # cloudinary.config(
        #         cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
        #         api_key=os.environ.get("CLOUDINARY_API_KEY"),
        #         api_secret=os.environ.get("CLODINARY_API_SECRET_KEY")
        #     )
        # uploaded_image = upload(graph_temp_file)

        # # Delete the temporary file
        # os.remove(graph_temp_file)
        # image_url = uploaded_image['secure_url']

        # # Save the model and vectorizer
        model_save_path = os.path.join(settings.BASE_DIR, 'spammodel', 'spam_detector_model.pkl')
        vectorizer_save_path = os.path.join(settings.BASE_DIR, 'spammodel', 'count_vectorizer.pkl')
        with open(model_save_path, 'wb') as model_file:
            print("Saving spam_detector_model.pkl")
            pickle.dump(clf, model_file)

        with open(vectorizer_save_path, 'wb') as vectorizer_file:
            print("Saving count_vectorizer.pkl")
            pickle.dump(count_vectorizer, vectorizer_file)

        return Response({"success":"Model trained successfully","accuracy":accuracy,"classification_report":classification_model_report,"graph_url":""}, status=status.HTTP_201_CREATED)
    class ModelGraph:
        def get(self,request):
            pass