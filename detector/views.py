from email import message
from django.shortcuts import render
from rest_framework.views import APIView,Response,status
from django.shortcuts import render
from django.http import JsonResponse
import pickle
import os
import json
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.errors import HttpError
from google.oauth2 import id_token
from google.auth.transport import requests
from google.auth.exceptions import GoogleAuthError
import googleapiclient.discovery
from google.oauth2 import credentials
from google.oauth2 import service_account
from googleapiclient.discovery import build
import requests as customRequest
from google.auth import transport,credentials
import google_auth_oauthlib.flow
from w3lib.url import url_query_parameter
import base64 
import re
# import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer 
from dotenv import load_dotenv
import nltk
import email
from email import message_from_bytes
from email.mime.text import MIMEText
import jwt
import requests
from rest_framework.serializers import ValidationError
from .serializers import CustomeUserSerializer
import random
import string
from django.contrib.auth.hashers import make_password
from rest_framework.exceptions import ValidationError
# nltk.download('stopwords')
# Create your views here.
load_dotenv()



class RegisterAuthVerify(APIView):
    def post(self, request):
        data=request.body
        data_string = data.decode('utf-8')
        auth_credentials = json.loads(data_string)
        print(auth_credentials)
        user=self.get_decoded_data(auth_credentials["creds"]["id_token"])
        print(user)
        user_serializer=CustomeUserSerializer(data=user)
        try:
            user_serializer.is_valid(raise_exception=True)
            user_serializer.save()
            print("Registered sucessfully")
            return Response("User Registered successfully ",status.HTTP_201_CREATED)
        except Exception as e:
            print("email is not valid")
            return Response("This email is already registered", status=status.HTTP_400_BAD_REQUEST)
       
    def validate_token(self,id_token):
        r = customRequest.get(
            "https://www.googleapis.com/oauth2/v3/tokeninfo",
            params={"id_token": id_token}
        )
        print("<>r<>",r)
        r.raise_for_status()
    def generate_random_password(self,email):
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        password_base = email.split('@')[0] + random_string
        return password_base
    def get_decoded_data(self,id_token):
        try:
            self.validate_token(id_token)
        except Exception:
            error = {"message": "Google token invalid."}
            raise ValidationError(error)
        else:
            data = jwt.decode(id_token, options={"verify_signature": False})
            # print("<>data<>",data)
            return {
                "password": self.generate_random_password(data["email"]),
                "email": data["email"],
                "name": data.get("name")
            }

# views.py
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from .serializers import CustomeUserSerializer

# class UserRegistrationView(APIView):
#     def post(self, request):
#         try:
#             auth_credentials = request.data.get("creds")
#             print("<>auth_credentials<>",auth_credentials)
#             if auth_credentials:
#                 id_token = auth_credentials.get("id_token")
#                 if id_token:
#                     user_data = self.get_decoded_data(id_token)
#                     user_serializer = CustomeUserSerializer(data=user_data)
#                     if user_serializer.is_valid():
#                         user_serializer.save()
#                         return Response("User Registered successfully", status=201)
#                     else:
#                         return Response(user_serializer.errors, status=400)
#             return Response("Invalid request", status=400)
#         except ValidationError as e:
#             return Response("Error..........", status=400)

#     def get_decoded_data(self, id_token):
#         data = jwt.decode(id_token, options={"verify_signature": False})
#         return {
#             "password": self.generate_random_password(data["email"]),
#             "email": data["email"],
#             "name": data.get("name")
#         }

#     def generate_random_password(self, email):
#         random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
#         password_base = email.split('@')[0] + random_string
#         return password_base




# class LoginAuthVerify(APIView):
#     def post(self,request):
#         data=request.body
#         data_string = data.decode('utf-8')
#         auth_credentials = json.loads(data_string)
#         # print(auth_credentials)
#         print(auth_credentials["creds"])
#         print(auth_credentials["creds"]["access_token"])
#         id_info = id_token.verify_oauth2_token(auth_credentials["creds"]["id_token"], requests.Request(), '"189496678458-fpihrhl6pae85mhtq0tsra89cpguccja.apps.googleusercontent.com"')
        
#         print(id_info)
#         return Response("loginsuccess",status=status.HTTP_200_OK)

class GoogleAuthVerify(APIView):
    
    def read_mail_with_content(self,service, message_id):
        try:
            print("called read_mail_with_content")
            message_raw = service.users().messages().get(userId="me", id=message_id).execute()
            raw_data = base64.urlsafe_b64decode(message_raw["raw"].encode()).decode()

            # Parse the raw email data
            message = message_from_bytes(raw_data)

            # Extract relevant information
            subject = message.get("Subject")
            sender = message.get("From")
            print("<>subject<>",subject)
            print("<>sender<>",sender)
            body = self.get_body_content(message.walk())

            # Format text for display (optional)
            # ... (you can implement your formatting logic here)
            
            print(body)
            return subject, sender, body
        except (KeyError, HttpError) as e:
            print(f"Error retrieving message {message_id}: {e}")
            return None, None, None

    def remove_html_tags(self,text):
        """Removes HTML tags from the text."""
        clean = re.sub(r'<.*?>', '', text)
        return clean

    def remove_punctuation(self,text):
        """Removes punctuation characters from the text."""
        clean = re.sub(r'[^\w\s]', '', text)
        return clean

    def lowercase_text(self,text):
        """Converts the text to lowercase."""
        return text.lower()

    def remove_stopwords(self,text):
        """Removes stopwords from the text."""
        stop_words = stopwords.words('english')
        clean = [word for word in text.split() if word not in stop_words]
        return clean

    def lemmatize_text(self,text):
        """Lemmatizes words in the text."""
        lemmatizer = WordNetLemmatizer()
        clean = [lemmatizer.lemmatize(word) for word in text]
        return clean

    def get_body_content(self,parts):
           for part in parts:
            #    print("<>part<>",part)
               if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    # text=base64.urlsafe_b64decode(data).decode()
                    # text = self.remove_html_tags(text)
                    # text = self.remove_punctuation(text)
                    # text = self.lowercase_text(text)
                    # text = self.remove_stopwords(text)
                    # text = self.lemmatize_text(text)
                    # print("body.......")
                    # print(" ".join(text))
                    # return " ".join(text)
                    return base64.urlsafe_b64decode(data).decode()
               elif part['mimeType'] == 'multipart/mixed' or 'multipart/alternative':
                   return self.get_body_content(part['parts'])
           return ''
    def get_credentials(self,code):
        # Implement user authorization flow or environment variable retrieval here
        # Following lines are for illustrative purposes only (DO NOT USE DIRECTLY)
        client_id = os.getenv("client_id")
        client_secret = os.getenv("client_secret")
        url = "https://oauth2.googleapis.com/token"
        payload = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri":"http://127.0.0.1:8000/api/google-auth-verify",
            "code": code
        }
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = customRequest.request("POST", url, headers=headers, data=payload)
        print(response.text)
        credentials=json.loads(response.text)
        return Credentials(token=credentials["access_token"])
    
    def get_gmail_api_service(self):
        credentials = self.get_credentials()
        http = credentials.authorize(http())
        return build('gmail', 'v1', http=http)

    def read_subject_and_body(self,service, message_id):
        try:
            message = service.users().messages().get(userId='me', id=message_id).execute()
            payload = message['payload']
            headers = payload['headers']

            # Extract subject
            subject = None
            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                    break

            # Extract body
            body = self.get_body_content(payload.get('parts', []))

            return subject, body
        except (KeyError, HttpError) as e:
            print(f"Error retrieving message {message_id}: {e}")
            return None, None

    def get(self,request):
        # code = request.GET.get('code1')
        code =request.GET.get("code")
        print(code)
        # self.get_credentials(code)
        url = "https://oauth2.googleapis.com/token"
        payload = {
            "grant_type": "authorization_code",
            "client_id": "189496678458-lbsabcd97iss894bi6c5tjmnrv1e3vh8.apps.googleusercontent.com",
            "client_secret": "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",
            "redirect_uri":"http://127.0.0.1:8000/api/google-auth-verify",
            "code": code
        }
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = customRequest.request("POST", url, headers=headers, data=payload)
        print(response.text)

        credentials=json.loads(response.text)
        print("credential",credentials)
        credentials = Credentials(token=credentials["access_token"])
        print("credential......",credentials)
        service = build('gmail', 'v1', credentials=credentials)
        # print("<<<<<<service",service)
        query = 'label:Inbox'  # You can set search criteria here (e.g., 'label:unread')

        # Get a list of message IDs
        response = service.users().messages().list(userId='me', q=query).execute()
        messages = response.get('messages', [])

        # Process a limited number of messages
        max_results = 20  # Adjust as needed
        results = []

        for i, message in enumerate(messages[:max_results]):
            msg_id = message['id']
            # self.read_mail_with_content(service,msg_id)


            # Get the full message details
            full_message = service.users().messages().get(userId='me', id=msg_id).execute()
            payload = full_message['payload']
            headers = payload['headers']

            # Extract subject
            subject = None
            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value'].rstrip()
                    break           

            # Extract the body parts
            try:
                parts = full_message['payload']['parts']
                # print("<>parts<>",parts)
                body = self.get_body_content(parts)
                results.append({'id': msg_id, 'header':subject,'body': body})
            except (KeyError, HttpError) as e:
                print(f"Error retrieving message {msg_id}: {e}")
        request.session["mail"]="aarti"
        print(request.session["mail"])
        return Response(results)
    def post(self,request):
        # code = request.GET.get('code1')
        # print(request.body)
        # code =request.GET.get("code")
        # data=request.body
        # data_string = data.decode('utf-8')
        # auth_credentials = json.loads(data_string)
        # print(auth_credentials["code"])
        # code =auth_credentials["code"]
        # # self.get_credentials(code)
        # url = "https://oauth2.googleapis.com/token"
        # payload = {
        #     "grant_type": "authorization_code",
        #     "client_id": "189496678458-lbsabcd97iss894bi6c5tjmnrv1e3vh8.apps.googleusercontent.com",
        #     "client_secret": "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",
        #     "redirect_uri":"http://127.0.0.1:8000/api/google-auth-verify",
        #     "code": code
        # }
        # headers = {
        # 'Content-Type': 'application/x-www-form-urlencoded'
        # }
        # response = customRequest.request("POST", url, headers=headers, data=payload)
        # print(response.text)

        # credentials=json.loads(response.text)
        # print("credential",credentials)
        # print(request.body)
        code =request.GET.get("code")
        data=request.body
        data_string = data.decode('utf-8')
        auth_credentials = json.loads(data_string)
        print(auth_credentials["access_token"])
        # return Response("login")
        credentials = Credentials(token=auth_credentials["access_token"])
        # print("credential......",credentials)
        service = build('gmail', 'v1', credentials=credentials)
        print("<<<<<<service",service)
        query = 'label:Inbox'  # You can set search criteria here (e.g., 'label:unread')

        # Get a list of message IDs
        response = service.users().messages().list(userId='me', q=query).execute()
        messages = response.get('messages', [])
        # print("<><>",messages)
        # Process a limited number of messages
        max_results = 10  # Adjust as needed
        results = []

        for i, message in enumerate(messages[:max_results]):
            msg_id = message['id']
            # self.read_mail_with_content(service,msg_id)


            # Get the full message details
            full_message = service.users().messages().get(userId='me', id=msg_id).execute()
            payload = full_message['payload']
            headers = payload['headers']

            # Extract subject
            subject = None
            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value'].rstrip()
                    break           

            # Extract the body parts
            try:
                parts = full_message['payload']['parts']
                # print("<>parts<>",parts)
                body = self.get_body_content(parts)
                results.append({'id': msg_id, 'header':subject,'body': body})
            except (KeyError, HttpError) as e:
                print(f"Error retrieving message {msg_id}: {e}")
        return Response(results)

class MailOperation(APIView):
    def get(self,request):
        inBoxMail=request.session.get("mail")
        print(inBoxMail)
        return Response(inBoxMail)
class Predict(APIView):
    def post(self,request):
        data = request.body
        # Decode the bytes to a string
        data_string = data.decode('utf-8')

        # Parse the string as JSON
        data_json = json.loads(data_string)
        message=data_json["message"]
        # Print the JSON object
        print(message)
        # Load the saved model and vectorizer
        model_path = os.path.join(os.path.dirname(__file__), 'spam_detector_model.pkl')
        vectorizer_path = os.path.join(os.path.dirname(__file__), 'count_vectorizer.pkl')
        with open(model_path, 'rb') as model_file:
            clf = pickle.load(model_file)
            print(clf)
        with open(vectorizer_path, 'rb') as vectorizer_file:
            count_vectorizer = pickle.load(vectorizer_file)
            print(count_vectorizer)
        # Make a prediction
        message_vector = count_vectorizer.transform([message])
        prediction = clf.predict(message_vector)
 
        return Response({'prediction': prediction[0]},status=status.HTTP_200_OK)
