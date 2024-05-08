from email import message
from tokenize import TokenError
from django.shortcuts import render
from rest_framework.views import APIView,Response,status
from django.shortcuts import render
from django.http import JsonResponse
import pickle
import os
from dotenv import load_dotenv
import json
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.errors import HttpError
from google.oauth2 import id_token
from google.auth.transport import requests
from google.auth.exceptions import GoogleAuthError
from rest_framework.permissions import IsAuthenticated,IsAdminUser,AllowAny
from rest_framework import permissions
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
import nltk
import email
from email import message_from_bytes
from email.mime.text import MIMEText
import jwt
import requests
from rest_framework.serializers import ValidationError
from rest_framework.pagination import PageNumberPagination
from .serializers import CustomeUserSerializer,EmailSerializer
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
from .models import TokenModel,CustomUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from django.contrib.auth import authenticate,login,logout
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.response import Response
from .pagination import MyPaginator
load_dotenv()

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
class LoginUser(APIView):
    def post(self,request):
        data=request.body
        user=request.user
        print(user)
        return Response("logout")


class Logout(APIView):
    def delete(self,request):
        user=request.user
        print(user)
        return Response("logout")
        # user, created =CustomUser.objects.get(email=user_email)
def get_auth_jwt_token(authenticatedUser):
        access_token=AccessToken.for_user(authenticatedUser)
        refresh_token=RefreshToken.for_user(authenticatedUser)
        token={"access_token":str(access_token),"refresh_token":str(refresh_token)}
        return token
class GoogleRegisterView(APIView):
    
    def generate_random_password(self,email):
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        password_base = email.split('@')[0] + random_string
        return password_base
    def saveCredentials(self,user_email="", google_access_token="",google_refresh_token="",jwt_refresh_token=""):
        user, created =CustomUser.objects.get_or_create(email=user_email)
        
        # Get or create a TokenModel instance for the user
        token_obj, _ = TokenModel.objects.get_or_create(userid=user)
        
        # Update the TokenModel instance with the access and refresh tokens
        token_obj.jwt_refresh_token=jwt_refresh_token
        token_obj.google_access_token=google_access_token
        token_obj.google_refresh_token = google_refresh_token
        print("token object",token_obj)
        token_obj.save()
    def post(self,request):
        authorization_code=request.body
        print("authorization_code",authorization_code)
        data_string = authorization_code.decode('utf-8')
        token_info = json.loads(data_string)
        google_access_token = token_info.get('access_token')
        google_refresh_token = token_info.get('refresh_token')  # Optional, depending on the scope
        user_info_url = f"https://www.googleapis.com/oauth2/v1/userinfo?access_token={google_access_token}"
        user_info_response = requests.get(user_info_url)
        if user_info_response.status_code == 200:
            user_info = user_info_response.json()
            print(user_info)
            # user_password=self.generate_random_password(user_info["email"])
            user={"email":user_info["email"],"name":user_info["name"]}
            try:
                user_serializer=CustomeUserSerializer(data=user)
                user_serializer.is_valid(raise_exception=True)
                authenticatedUser=user_serializer.save()
                print("obj",authenticatedUser)
                jwt_token=get_auth_jwt_token(authenticatedUser)
                self.saveCredentials(user["email"],google_access_token=google_access_token,google_refresh_token=google_refresh_token,jwt_refresh_token=jwt_token["refresh_token"])
                login(request,authenticatedUser)
                print("logged in user",authenticatedUser)
                return Response({"message":"User Registered successfully","access_token":jwt_token["access_token"],"refresh_token":jwt_token["refresh_token"]},status.HTTP_201_CREATED)
            except ValidationError as e:
                print(str(e))
                google_access_token = token_info.get('access_token')
                google_refresh_token = token_info.get('refresh_token')
                authenticatedUser=CustomUser.objects.get(email=user["email"])
                User_Token_cred=TokenModel.objects.get(userid=authenticatedUser)
                User_Token_cred.google_access_token=google_access_token
                User_Token_cred.google_refresh_token=google_refresh_token
                jwt_refresh_token=User_Token_cred.jwt_refresh_token
                access_token_response=customRequest.post("http://127.0.0.1:8000/api/refreshtoken/",data=jwt_refresh_token,timeout=20)
                jwt_access_token=access_token_response.json()
                print("jwt_access_token",jwt_access_token)
                print("jwt_refresh_token",jwt_refresh_token)
                res=User_Token_cred.save()
                print(res)
                login(request,authenticatedUser)
                return Response({"message":"User Logged in successfully","access_token":jwt_access_token["access_token"],"refresh_token":jwt_refresh_token},status.HTTP_200_OK)
            except Exception as e:
                print(f"64 Error {str(e)} ")
                return Response(f"Error {str(e)}",status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Failed to fetch user info from Google'}, status=status.HTTP_400_BAD_REQUEST)
class GoogleLoginView(APIView):
    def post(self, request):
        # access_token = request.data.get('access_token')
        data=request.body
        data=data.decode('utf-8')
        login_data=json.loads(data)
        try:
            authenticate_user=authenticate(request,email=login_data["email"],password=login_data["password"])
            if(authenticate_user):
                User_Token_cred=TokenModel.objects.get(userid=authenticate_user)
                if(User_Token_cred):
                    google_access_token=User_Token_cred.google_access_token
                    jwt_refresh_token=User_Token_cred.jwt_refresh_token

                    user_info_url = f"https://www.googleapis.com/oauth2/v1/userinfo?access_token={google_access_token}"
                    user_info_response = requests.get(user_info_url)
                    print("user_info_response",user_info_response.text)
                    if user_info_response.status_code == 200:
                        access_token_response=customRequest.post("http://127.0.0.1:8000/api/refreshtoken/",data=jwt_refresh_token)
                        access_token=access_token_response.json()
                        login(request,authenticate_user)
                        print("response access_token",access_token)
                        return Response({"message":"Login successfully","access_token":access_token["access_token"],"refresh_token":jwt_refresh_token}, status=status.HTTP_200_OK)
                    else:
                        return Response({'error': 'Failed to fetch user info from Google'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response("Please login with google")
            else:
                print("user not found")
                return Response("user not found")
        except Exception as e:
            print(str(e))
            return Response(f"Error ${str(e)}")
        
class TokenRefresh(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        print("called")
        data=request.body
        print("data",data)
        refresh_token=data.decode('utf-8')
        print(refresh_token)
        try:
            access_token_obj=RefreshToken(refresh_token)
            access_token = str(access_token_obj.access_token)
            return Response({"access_token":access_token})
        except Exception as e:
            return Response({'error': str(e)})

class MailRead(APIView):
    permission_classes=[IsAuthenticated]
    pagination_class = PageNumberPagination 

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
    def fetch_emails(self, service, query, max_results=2):
        try:
            response = service.users().messages().list(userId='me', q=query).execute()
            messages = response.get('messages', [])
            results = []

            for message in messages[:max_results]:
                msg_id = message['id']
                full_message = service.users().messages().get(userId='me', id=msg_id).execute()
                payload = full_message['payload']
                # print("payload",payload)
                headers = payload['headers']
                sender = next((header['value'] for header in headers if header['name'] == 'From'), None)
                subject = next((header['value'] for header in headers if header['name'] == 'Subject'), None)
                date = next((header['value'] for header in headers if header['name'] == 'Date'), None)
                # print(subject)
                parts = payload.get('parts', [])
                body = self.get_body_content(parts)
                # print("Body in mail read",body)
                # body_without_link=self.remove_links_and_whitespace(body)
                # print("body_without_link",body_without_link)
                predict_response = customRequest.post('http://127.0.0.1:8000/api/predict/',body)
                # print("predict_response",predict_response.text)
                prediction_data = predict_response.json()
                # print("prediction_data",prediction_data["prediction"])
                spamOrNot=""
                if(prediction_data["prediction"]=="spam"):
                    spamOrNot=True
                else:
                    spamOrNot=False
                
                # body = self.get_body_content(payload['parts'])
                results.append({'id': msg_id, 'header': subject, 'body': body,"date":date,'sender':sender,"spam":spamOrNot})       
            return results
        except HttpError as e:
            print(f"Error fetching emails: {e}")
            return []
    def get(self, request):
            print(request.user)
            lable_query = request.GET.get("querylable")
            message_limit=request.GET.get("msglimit")
            print(TokenModel.objects.get(userid=request.user.id))
            User_Token_cred=TokenModel.objects.get(userid=request.user.id)
            if(User_Token_cred):
                access_token=User_Token_cred.google_access_token
                refresh_token=User_Token_cred.google_refresh_token
            else:
                return Response("Please login with google")
            print("lable query",lable_query)
            CLIENT_SECRET=os.environ.get("CLIENT_SECRET")
            CLIENT_ID=os.environ.get("CLIENT_ID")
            access_token = request.GET.get("access_token")
            credentials = Credentials(token=access_token,token_uri=os.environ.get("ToKEN_URI"), refresh_token=refresh_token, client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
            # Check if the credentials is expired
            if credentials.expired:
                # Refresh the token
                print("token got refresh")
                request = requests.Request()
                credentials.refresh(request)   
            service = build('gmail', 'v1', credentials=credentials)
            query = f'label:{lable_query}'
            results = self.fetch_emails(service, query,max_results=int(message_limit))
            # page = self.request.query_params.get('page', 1)
            page_size = self.request.query_params.get('page_size', 10) 
            # print("page",page)
            paginator = self.pagination_class()
            paginator.page_size=page_size
            paginated_results = paginator.paginate_queryset(results, request)
            print(paginated_results)
            email_serializer = EmailSerializer(paginated_results, many=True)
            return paginator.get_paginated_response({"data":email_serializer.data})
            return paginator.get_paginated_response({"data":paginated_results})
    def handle_exception(self, exc):
        # Override the default exception handler to return custom response for unauthenticated users
        if isinstance(exc, permissions.IsAuthenticated):
            print("called error")
            return Response({"error": "You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
class ComposeMail(APIView):
    def post(self, request):
        try:
            data = request.body
            data_string = data.decode('utf-8')
            credentials = json.loads(data_string)
            credentials["client_secret"]=os.environ.get("CLIENT_SECRET")
            credentials["client_id"]=os.environ.get("CLIENT_ID")

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
        message = data.decode('utf-8')
        # print(message)
        #preprocess data
        cleaned_body = self.preprocess_email_body(message)
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
