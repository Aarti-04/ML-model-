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
from django.contrib.auth import authenticate,login,logout
import base64
from email.message import EmailMessage

import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from rest_framework.views import APIView
from rest_framework.response import Response
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth import default
from google.auth.exceptions import DefaultCredentialsError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
import json
from google.oauth2.credentials import Credentials


# from rest_framework.views import APIView, Response
# from django.http import JsonResponse
# import os
# import json
# from google.oauth2.credentials import Credentials
# from google_auth_oauthlib.flow import InstalledAppFlow
# from googleapiclient.errors import HttpError
# import googleapiclient.discovery
# from google.oauth2 import service_account
# import requests
# from dotenv import load_dotenv
# import nltk
# import email
# from nltk.corpus import stopwords
# from nltk.stem import WordNetLemmatizer
# import re
# import jwt
# import random
# import string
# from django.contrib.auth.hashers import make_password
# from rest_framework.exceptions import ValidationError
# from django.contrib.auth import authenticate, login, logout
# from email.message import EmailMessage

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
            print("user_serializer",user_serializer)
            # login(request,user_serializer)
            return Response("User Registered successfully ",status.HTTP_201_CREATED)
        except Exception as e:
            print(f"64 Error {str(e)} ")
            return Response("Email already exist")
            # raise ValidationError(str(e))
    def validate_token(self,id_token):
        r = customRequest.get(
            "https://www.googleapis.com/oauth2/v3/tokeninfo",
            params={"id_token": id_token}
        )
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
      # text=base64.urlsafe_b64decode(data).decode()
                    # text = self.remove_html_tags(text)
                    # text = self.remove_punctuation(text)
                    # text = self.lowercase_text(text)
                    # text = self.remove_stopwords(text)
                    # text = self.lemmatize_text(text)
                    # print("body.......")
                    # print(" ".join(text))
                    # return " ".join(text)

    def get_body_content(self,parts):
           for part in parts:
            #    print("<>part<>",part)
               if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    return base64.urlsafe_b64decode(data).decode()
               elif part['mimeType'] == 'multipart/mixed' or 'multipart/alternative':
                   return self.get_body_content(part['parts'])
           return '' 
    def post(self,request):
        lable_query =request.GET.get("querylable")
        print(lable_query)
        data=request.body
        data_string = data.decode('utf-8')
        auth_credentials = json.loads(data_string)
        print(auth_credentials["access_token"])
        # return Response("login")
        credentials = Credentials(token=auth_credentials["access_token"])
        # print("credential......",credentials)
        service = build('gmail', 'v1', credentials=credentials)
        query = f'label:{lable_query}'  # You can set search criteria here (e.g., 'label:unread')

        # Get a list of message IDs
        response = service.users().messages().list(userId='me', q=query).execute()
        messages = response.get('messages', [])
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
class MailRead(APIView):
    def get_body_content(self, parts):
        if not parts:
            return ''
        for part in parts:
            if part.get('mimeType') == 'text/plain':
                data = part['body']['data']
                return base64.urlsafe_b64decode(data).decode()
            elif part.get('mimeType') == 'text/html':
                data = part['body']['data']
                return base64.urlsafe_b64decode(data).decode()
            elif part.get('mimeType') in ('multipart/mixed', 'multipart/alternative'):
                return self.get_body_content(part.get('parts', []))
        return ''
    def fetch_emails(self, service, query, max_results=10):
        try:
            response = service.users().messages().list(userId='me', q=query).execute()
            messages = response.get('messages', [])
            results = []

            for message in messages[:max_results]:
                msg_id = message['id']
                full_message = service.users().messages().get(userId='me', id=msg_id).execute()
                payload = full_message['payload']
                headers = payload['headers']
                subject = next((header['value'] for header in headers if header['name'] == 'Subject'), None)
                print(subject)
                parts = payload.get('parts', [])
                body = self.get_body_content(parts)
                # body = self.get_body_content(payload['parts'])
                results.append({'id': msg_id, 'header': subject, 'body': body})
                
            return results
        except HttpError as e:
            print(f"Error fetching emails: {e}")
            return []
    def post(self, request):
        lable_query = request.GET.get("querylable")
        data = request.body
        data_string = data.decode('utf-8')
        auth_credentials = json.loads(data_string)
        access_token = auth_credentials["access_token"]

        credentials = Credentials(token=access_token)
        service = build('gmail', 'v1', credentials=credentials)
        query = f'label:{lable_query}'

        results = self.fetch_emails(service, query)

        return Response(results)
class ComposeMail(APIView):
    def post(self, request):
        try:
            data = request.body
            data_string = data.decode('utf-8')
            credentials = json.loads(data_string)
            credentials["client_secret"]="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"
            credentials["client_id"]="189496678458-fpihrhl6pae85mhtq0tsra89cpguccja.apps.googleusercontent.com"

            # Initialize credentials using access token
            creds = Credentials(token=credentials["access_token"])
            scopes = ['https://www.googleapis.com/auth/gmail.compose']
            creds1 = Credentials.from_authorized_user_info(credentials, scopes=scopes)
            print(creds1)
            # Build Gmail service
            service = build("gmail", "v1", credentials=creds)

            # Get user's email address
            user_info = service.users().getProfile(userId='me').execute()
            user_email = user_info['emailAddress']
            # return Response(user_email)
            # Construct the email message
            message = MIMEMultipart()
            message['to'] = "sharma.aart.dcs24@vnsgu.ac.in"
            message['from'] = user_email
            message['subject'] = "Automated draft"

            # Add email body
            body = "This is automated draft mail"
            message.attach(MIMEText(body, 'plain'))

            # Encoded message
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

            # Create draft message
            draft_message = {"message": {"raw": raw_message}}
            draft = service.users().drafts().create(userId="me", body=draft_message).execute()

            return Response({"message": "Mail draft created successfully"})
        
        except DefaultCredentialsError:
            return Response({"error": "Authentication error. Ensure you have valid credentials."})
        
        except Exception as e:
            print(f"An error occurred: {e}")
            return Response({"error": "Failed to create mail draft"})
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
