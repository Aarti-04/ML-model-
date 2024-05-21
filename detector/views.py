import csv
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
from bs4 import BeautifulSoup
from .gmail_service import get_gmail_service
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
from rest_framework import generics
from rest_framework.response import Response
from googleapiclient.discovery import build
from google.auth import default
from google.auth.exceptions import DefaultCredentialsError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
import json
from google.oauth2.credentials import Credentials
from .models import TokenModel,CustomUser,EmailMessageModel
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from django.contrib.auth import authenticate,login,logout
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.response import Response
from .pagination import MyPaginator
from rest_framework import generics,pagination
from rest_framework.filters import SearchFilter,OrderingFilter
from datetime import datetime
import asyncio
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.signals import user_logged_in
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split,cross_val_score
from sklearn.metrics import accuracy_score, classification_report
import pickle
from sklearn import svm
# from imblearn.over_sampling import RandomOverSampler
# from imblearn.under_sampling import RandomUnderSampler
import numpy as np
from django.conf import settings

load_dotenv()


EMAIL_PATTERN = re.compile(r'<([^<>]+)>')
class LoginUser(APIView):
    def post(self,request):
        data=request.body
        user=request.user
        print(user)
        return Response("logout")


class Logout(APIView):
    parser_classes=[IsAuthenticated]
    def delete(self,request):
        user=request.user
        print(user)
        logout(request)
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
                user_logged_in.send(sender=CustomUser,request=request,user=authenticatedUser)
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


class MailDeleteDb(APIView):
    permission_classes=[IsAuthenticated]
    def delete(self,request):
        try:
            message_id = request.query_params.get('message_id')  # Assuming 'query_type' is the query parameter to specify sent or inbox
            message_object = EmailMessageModel.objects.get(id=message_id)
            if(message_object):
                setattr(message_object,"is_deleted",True)
                message_object.save()
                return Response("Email deleted successfully",status=status.HTTP_200_OK)
            else:
                return Response("Mail not exsist",status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(f"Error {str(e)}",status=status.HTTP_500_INTERNAL_SERVER_ERROR)            
    
class MailFromDb(generics.ListCreateAPIView):
    # queryset=EmailMessageModel.objects.all()
    
    serializer_class=EmailSerializer
    permission_classes=[IsAuthenticated]
    pagination_class=pagination.PageNumberPagination
    pagination_class.page_size=10
    filter_backends=[SearchFilter,OrderingFilter]
    search_fields = ['header', 'sender', 'recipient']  # Specify the fields you want to enable search on

    # Define fields to sort
    ordering_fields = ['id', 'header', 'sender', 'recipient', 'date']  # Specify the fields you want to enable sorting on

    # By default, if no ordering is provided, order by timestamp in descending order
    ordering = ['-date']
    def get_queryset(self):
        queryset = EmailMessageModel.objects.all().order_by("-date")
        query_type = self.request.query_params.get('query_type')
          # Assuming 'query_type' is the query parameter to specify sent or inbox
        if query_type == 'sent':
            queryset = queryset.filter(sender=self.request.user,is_archived=False,is_deleted=False)  # Filter emails sent by the authenticated user
        elif query_type == 'inbox':
            queryset = queryset.filter(recipient=self.request.user,is_archived=False,is_deleted=False) 
        elif query_type=="spam":
            queryset = queryset.filter(spam=True,is_archived=False,is_deleted=False) 
             # Filter emails received by the authenticated user
        elif query_type=="archive":
            queryset = queryset.filter(is_archived=True) 
        # print("queryset",queryset)
        
        return queryset
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        queryset = self.paginate_queryset(queryset)
        processed_emails = []

        for email in queryset:
            # Fetch mail body
            mail_body = email.body  # Assuming you have a field named 'body' in your EmailMessageModel
            
            # Send request to prediction API
            prediction_api_url = 'http://127.0.0.1:8000/model/predict/'
            data = {'body': mail_body}
            json_mail_body=json.dumps(data)
            print("calledddddd json_mail_body",queryset)

            # Adjust this according to the API's requirements
            response = requests.post(prediction_api_url, data=json_mail_body,headers={'Content-Type': 'application/json'},timeout=20)
            print("response.text",response.text)
            print(response.status_code)
            
            # Modify 'spam' field based on prediction
            if response.status_code == 200:
                prediction_result = response.json()
                is_spam = prediction_result['is_spam']  # Assuming the API returns a field 'is_spam'
            is_spam=is_spam
            print("is_spam...",is_spam)
            # email.spam = is_spam
            setattr(email,"spam",is_spam)
            email.save()

            processed_data = {
                'id':email.id,
                # 'user_id':email.user_id,
                'message_id':email.message_id,
                'header': email.header,
                'body':email.body,
                'date':email.date,
                'sender': email.sender,
                'recipient': email.recipient,
                'snippet': email.snippet,
                'spam': is_spam,
                'is_archived':email.is_archived,
                'is_deleted':email.is_deleted
                # Add more fields as needed
            }
            processed_emails.append(processed_data)
            # else:
                # print("predict failed")
                # If prediction API fails, you can handle it accordingly
                # For example, log the error or skip this email
                # pass
        
        return self.get_paginated_response(processed_emails)
    
class MailRead(APIView):
    # permission_classes=[IsAuthenticated]
    pagination_class = PageNumberPagination 

    def extract_email_info(self,data):
        processed_mail_data=data
        processed_mail_data["date"] = datetime.strptime(data["date"].replace(' (UTC)', ''), '%a, %d %b %Y %H:%M:%S %z')
        recipient_email_matched=re.search(EMAIL_PATTERN,data["recipient"])
        processed_mail_data["recipient"]=recipient_email_matched.group(1) if recipient_email_matched else data["recipient"].strip()
        sender_email_matched=re.search(EMAIL_PATTERN,data["sender"])
        processed_mail_data["sender"]=sender_email_matched.group(1) if sender_email_matched else data["sender"].strip()
        print(processed_mail_data)
        return  processed_mail_data

    def save_mail_data(self,mail_data):
        try:
            print(datetime.time)
            for mail in mail_data:
                # print("mail id........",mail["id"])
                print("mail...",mail)
                exist_mail=EmailMessageModel.objects.filter(message_id=mail["message_id"]).exists()
                # mail["user_id"]=user_email
                print("exist_mail",exist_mail)
                processed_data=self.extract_email_info(mail)
                # date_string_without_timezone = mail["date"].replace(' (UTC)', '')
                # # Parse the date string
                # mail["date"] = datetime.strptime(date_string_without_timezone, '%a, %d %b %Y %H:%M:%S %z')
                
                # # mail["date"] = datetime.strptime(mail["date"], '%a, %d %b %Y %H:%M:%S %z')
                # print("mail[date]", mail["date"])
                if not exist_mail:
                    # created=EmailMessageModel.objects.create(**mail)
                    # s=created.save()
                    print("not exist...")
                    serialized_email=EmailSerializer(data=processed_data,many=False)
                    try:
                        if(serialized_email.is_valid(raise_exception=True)):
                            created=serialized_email.save()
                            print("created......",created)
                            # print("____",s)
                    except Exception as e:
                            print(f"error...${str(e)}")
                else:
                    print("in else")
                    break
        except Exception as e:
            print(str(e))
        print(datetime.time)

    def get_body_content(self, parts):
        body=''
        if not parts:
            return body
        for part in parts:
            if part.get('mimeType') == 'text/plain':
                data1 = part['body']['data'] 
                if data1:
                    print("data1",data1)
            if part.get('mimeType') == 'text/html':
                data = part['body']['data']
                if data:
                    body=base64.urlsafe_b64decode(data).decode()
                else:
                    body=""

            # elif part.get('mimeType') in ('multipart/mixed', 'multipart/alternative'):
                # body += self.get_body_content(part.get('parts', []))
        return body
    async def fetch_emails(self, service, query,max_results=10):
        try:
            response = await service.users().messages().list(userId='me', q=query,maxResults=max_results).execute()
            # result_size_estimate = response.get('resultSizeEstimate', 0)
            messages = response.get('messages', [])
            results = []
            # print("response",response)
            # print("messages",len(messages))
            # print("result_size_estimate",result_size_estimate)
            for message in messages[:max_results]:
                msg_id = message['id']
                full_message = service.users().messages().get(userId='me', id=msg_id).execute()
                payload = full_message['payload']
                # print("payload",payload)
                headers = payload['headers']
                snippet=full_message["snippet"]
                print("snippet...",snippet)
                sender = next((header['value'] for header in headers if header['name'] == 'From'), None)
                To = next((header['value'] for header in headers if header['name'] == 'To'), None) 
                subject = next((header['value'] for header in headers if header['name'] == 'Subject'), None)
                date = next((header['value'] for header in headers if header['name'] == 'Date'), None)
                print("date of mail",date)
                parts = payload.get('parts', [])
                body = self.get_body_content(parts)
                # print("BodyText",body)
                predict_response = customRequest.post('http://127.0.0.1:8000/api/predict/',body)
                # print("predict_response",predict_response.text)
                prediction_data = predict_response.json()
                spamOrNot=True if(prediction_data["prediction"]=="spam") else False
                results.append({'snippet':snippet,'message_id': msg_id, 'header': subject, "body":body,"date":date,'sender':sender,"recipient":To,"spam":spamOrNot})       
            return results
        except HttpError as e:
            print(f"Error fetching emails: {e}")
            return [],0
    def get(self, request):
            # user_email=request.user
            # lable_query = request.GET.get("querylable")
            # message_limit=request.GET.get("msglimit")
            # print(TokenModel.objects.get(userid=request.user.id))
            User_Token_cred=TokenModel.objects.get(userid=request.user.id)
            if(User_Token_cred):
                access_token=User_Token_cred.google_access_token
                refresh_token=User_Token_cred.google_refresh_token
            else:
                return Response("Please login with google")
            # print("lable query",lable_query)
            CLIENT_SECRET=os.environ.get("CLIENT_SECRET")
            CLIENT_ID=os.environ.get("CLIENT_ID")
            credentials = Credentials(token=access_token,token_uri=os.environ.get("ToKEN_URI"), refresh_token=refresh_token, client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
            # Check if the credentials is expired
            if credentials.expired:
                # Refresh the token
                print("token got refresh")
                request = requests.Request()
                credentials.refresh(request)   
            service = build('gmail', 'v1', credentials=credentials)
            # query = f'label:{lable_query}'
            query=""
            results = self.fetch_emails(service, query)
            # page = self.request.query_params.get('page', 1)
            # page_size = self.request.query_params.get('page_size',10) 
            paginator = self.pagination_class()
            paginator.page=1
            paginator.page_size=10
            # paginator.count=result_size_estimate
            paginated_results = paginator.paginate_queryset(results, request)
            # print("paginated_results",paginated_results)
            email_serializer = EmailSerializer(paginated_results, many=True)
            # print("paginated_results",paginated_results)
            self.save_mail_data(paginated_results)
            return paginator.get_paginated_response({"data":email_serializer.data})
    def handle_exception(self, exc):
        # Override the default exception handler to return custom response for unauthenticated users
        if isinstance(exc, permissions.IsAuthenticated):
            print("called error")
            return Response({"error": "You are not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)
# class MailDataSearchAndSort(APIView):
#     def get(self,request):
#         search=request.GET.get("search") or ""
#         order_by=request.GET.get("orderby") or "updated_at" 
#         return Response("")
        
class MailArchived(APIView):
    def patch(self,request):
        try:
            message_id=request.query_params.get("message_id")
            print("called",message_id)
            if not message_id:
                raise ValidationError("message id invalid or not provided")
                 
            message_object=EmailMessageModel.objects.filter(id=message_id).first()
            print(message_object)
            if not message_object:
                raise ObjectDoesNotExist("Mail not exist")
            if(message_object.is_archived):
                return Response("Already in archived ",status=status.HTTP_400_BAD_REQUEST)
            setattr(message_object,"is_archived",True)
            print(message_object.is_archived)
            res=message_object.save()
            print(res)
            return Response("Messsage archived successfully",status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response(e.detail,status=status.HTTP_400_BAD_REQUEST)
        except ObjectDoesNotExist as e:
            return Response(f"Mail data not exist {e}",status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"Error..{str(e)}")
            return Response(f"{str(e)}",status=status.HTTP_400_BAD_REQUEST)
class ComposeMail(APIView):
    permission_classes=[IsAuthenticated]
    def gmail_compose(self,mail_subject, email_recipient, mail_body):
        message = {
            'raw': base64.urlsafe_b64encode(
                f'MIME-Version: 1.0\n'
                f'Content-Type: text/html; charset="UTF-8"\n'
                f"From: itbase.tv@gmail.com\n"
                f"To: {email_recipient}\n"
                f"Subject: {mail_subject}\n\n"
                f"{mail_body}"
                .encode("utf-8")
            ).decode("utf-8")
        }
        return message
    def gmail_send(self,service, message):
        # Send the email
        # service = build('gmail', 'v1', credentials=creds)
        try:
            service.users().messages().send(userId='me', body=message).execute()
            print('Email sent successfully.')
            return True
        except Exception as e:
            print('An error occurred while sending the email:', str(e))
            return False

    def post(self, request):
        try:
            data = request.body.decode('utf-8')
            print(data)
            # Decode the bytes to a string
            message_data=json.loads(data)
            if(not message_data):
                return Response("body can't be empty",status=status.HTTP_400_BAD_REQUEST)
            header=message_data.get("header")
            to=message_data.get("recipient")
            mail_body=message_data.get("body")
            gmail_service=get_gmail_service(request.user)
            # header="Test Mail from django"
            # to="sharma.aarti.dcs24@vnsgu.ac.in"
            # mail_body="<html><h1>hello user how are you doing?</h1><br><br><h3>you have won 10 lacs case prize please go through bellow link and get complete your process</h3></html>"
            message_to_send=self.gmail_compose(header,to,mail_body)
            message_send_or_not=self.gmail_send(gmail_service,message_to_send)
            if(message_send_or_not):
                return Response({"success":"Mail Sent successfully"},status=status.HTTP_200_OK)
        except Exception as e:
            print(f"An error occurred: {e}")
            return Response({"error": "Failed to create mail"},status=400)
class Feedback(APIView):
    def post(self, request):
        message_id = request.data.get('message_id')
        EmailMessage=EmailMessageModel.objects.get(id=message_id)
        email_body=EmailMessage.body
        
        correct_label = request.data.get('label')  # 'ham' or 'spam'

        # Save feedback to a file or database
        feedback_path = os.path.join(settings.BASE_DIR, 'spammodel', 'user_feedback.csv')
        with open(feedback_path, 'a') as f:
            writer = csv.writer(f)
            writer.writerow([correct_label, message])

        return Response("Feedback received", status=status.HTTP_201_CREATED)
