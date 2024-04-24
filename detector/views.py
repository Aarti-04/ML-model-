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
# Create your views here.
class GoogleAuthVerify(APIView):
    
    def auth(self,credential_code=""):
        # id_info = id_token.verify_oauth2_token(credential, requests.Request(), '189496678458-qimsru4vsjae5tvfisn17gp7nh0v527k.apps.googleusercontent.com')
        # print(id_info)
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file('client_credential.json',scopes=['https://www.googleapis.com/auth/drive.metadata.readonly'])
        flow.redirect_uri = 'http://127.0.0.1'

        # Generate URL for request to Google's OAuth 2.0 server.
        # Use kwargs to set optional request parameters.
        authorization_url, state = flow.authorization_url(
        # Recommended, enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Optional, enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true',
        prompt='consent')
        # url = authorization_url
        # print(authorization_url)
        state=url_query_parameter(authorization_url, 'state')
        print(state)
        url_to_get_code=f"https://accounts.google.com/o/oauth2/auth?client_id=189496678458-lbsabcd97iss894bi6c5tjmnrv1e3vh8.apps.googleusercontent.com&redirect_uri=http://127.0.0.1&scope=https://www.googleapis.com/auth/gmail.readonly&email&response_type=code&include_granted_scopes=true&access_type=offline&state={state}"
        print(url_to_get_code)
        code_res=customRequest.get(url_to_get_code)
        print(code_res.text)
        # r=customRequest.post(f"https://accounts.google.com/o/oauth2/auth?client_id=189496678458-lbsabcd97iss894bi6c5tjmnrv1e3vh8.apps.googleusercontent.com&redirect_uri=http://127.0.0.1&scope=https://www.googleapis.com/auth/gmail.readonly&email&response_type=code&include_granted_scopes=true&access_type=offline&state={state}")
        # print(r.text)
        # token_url="https://accounts.google.com/o/oauth2/auth"
        # payload = {
        #         "grant_type": "authorization_code",
        #         "client_id": "189496678458-lbsabcd97iss894bi6c5tjmnrv1e3vh8.apps.googleusercontent.com",
        #         "client_secret": "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",
        #         "redirect_uri": "http://127.0.0.1",
        #         "code": credential_code ,
        #         "scope":"https://www.googleapis.com/auth/gmail.readonly",
        #         "include_granted_scopes":"true",
        #         "access_type":"offline",
        #         "state":state
        # }
        # headers = {"Content-Type": "application/x-www-form-urlencoded"}
        # response = customRequest.post(token_url, data=payload, headers=headers)
        # with open("temp.txt","w") as f:
        #     f.write(response.text)
        # # print(response.text)
        # return response

    def get_body_content(self, parts):
           for part in parts:
               if part['mimeType'] == 'text/plain':
                   data = part['body']['data']
                   d=base64.urlsafe_b64decode(data).decode()
                   return base64.urlsafe_b64decode(data).decode()
               elif part['mimeType'] == 'multipart/mixed' or 'multipart/alternative':
                   return self.get_body_content(part['parts'])
           return ''
    def get_credentials():
        # Implement user authorization flow or environment variable retrieval here
        # Following lines are for illustrative purposes only (DO NOT USE DIRECTLY)
        client_id = "YOUR_CLIENT_ID"
        client_secret = "YOUR_CLIENT_SECRET"
        return Credentials(token="YOUR_ACCESS_TOKEN")

    def get(self,request):
        # code = request.GET.get('code1')
        code =request.GET.get("code")
        print("<>code<>",code)
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
        credentials = Credentials(token=credentials["access_token"])
        service = build('gmail', 'v1', credentials=credentials)
        # print(service)
        query = 'label:inbox'  # You can set search criteria here (e.g., 'label:unread')

        # Get a list of message IDs
        response = service.users().messages().list(userId='me', q=query).execute()
        messages = response.get('messages', [])

        # Process a limited number of messages
        max_results = 10  # Adjust as needed
        results = []

        for i, message in enumerate(messages[:max_results]):
            msg_id = message['id']

            # Get the full message details
            full_message = service.users().messages().get(userId='me', id=msg_id).execute()
            # print("<>full message<>",full_message)

            # Extract the body parts (handling potential errors)
            try:
                parts = full_message['payload']['parts']
                # print("<>parts<>",parts)
                body = self.get_body_content(parts)
                results.append({'id': msg_id, 'body': body})
            except (KeyError, HttpError) as e:
                print(f"Error retrieving message {msg_id}: {e}")
        
        return Response(results)

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
