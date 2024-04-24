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

    def auth_with_python(self):
        SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
        creds = None
        # The file token.json stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if os.path.exists("token.json"):
            creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_config(
                    {
                       "web": {
                                "client_id": "189496678458-qimsru4vsjae5tvfisn17gp7nh0v527k.apps.googleusercontent.com",
                                "project_id": "webapplication-419117",
                                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                                "token_uri": "https://oauth2.googleapis.com/token",
                                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                                "client_secret": "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",
                                "redirect_uris": ["http://127.0.0.1:8000/api/google-auth-verify/"],
                                "javascript_origins": ["http://localhost", "http://localhost:3000"]
                            }
                    }, SCOPES
                )
                creds = flow.run_local_server(port=0)
                print("<><>",creds)
            # Save the credentials for the next run
            with open("token.json", "w") as token:
                token.write(creds.to_json())
        # try:
        #     service = build("gmail", "v1", credentials=creds)
        #     # Call the Gmail v1 API
        #     results = (
        #         service.files()
        #         .list(pageSize=10, fields="nextPageToken, files(id, name)")
        #         .execute()
        #     )
        #     items = results.get("files", [])
        #     if not items:
        #         print("No files found.")
        #         return
        #     print("Files:")
        #     for item in items:
        #         print(f"{item['name']} ({item['id']})")
        # except HttpError as error:
        #     # TODO(developer) - Handle errors from drive API.
        #     print(f"An error occurred: {error}")
    def verify_auth(self,credential_token):
        
        id_info = id_token.verify_oauth2_token(credential_token, requests.Request(), '189496678458-qimsru4vsjae5tvfisn17gp7nh0v527k.apps.googleusercontent.com')

        credentials = Credentials.refresh_token()
        print(id_info)
        gmail_service = build('gmail', 'v1', credentials=credentials)
        response = gmail_service.users().messages().list(userId='me').execute()
        messages = []

        if 'messages' in response:

            messages.extend(response['messages'])

            # If there are more messages, paginate through the results
            while 'nextPageToken' in response:
                page_token = response['nextPageToken']
                response = gmail_service.users().messages().list(userId='me', pageToken=page_token).execute()
                messages.extend(response['messages'])

        # Fetch the content of each message
        print("heyy")
        for message in messages:
            msg_id = message['id']
            msg = gmail_service.users().messages().get(userId='me', id=msg_id).execute()
            print("Message snippet: ", msg['snippet'])

    def gmail_access_using_access_refresh_token(self,access_token="",refresh_token=""):
       
        client_id="189496678458-qimsru4vsjae5tvfisn17gp7nh0v527k.apps.googleusercontent.com"
        client_secret="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"
        creds_with_access_token_and_refresh_token={
                "access_token": "OKX-NiAP38mxMY-1U-54mvqAL8BjmBg5UEQRekkHdglIVw-6SJPSm1xMQVX5MhZg-uTV6PZKx_vRi6Ua05yRnwYswhTyJg2YPP91nnDseejVYTIXaCgYKAasSARESFQHGX2MiPU-ww_mrHAcOM2GNMa3wtw0171", 
                "scope": "https://www.googleapis.com/auth/gmail.readonly", 
                "token_type": "Bearer", 
                "expires_in": 3599, 
                "refresh_token": "1//04uM2aSyciVJqCgYIARAAGAQSNwF-L9IrZ5MgRhQKRudEC_x5DJTw1R5utbCOmxtSJMmCyTTNLbUZGZ17h1y1sm5v7OcdCe32yQw"
        }
        creds = credentials.Credentials(token=None,refresh_token=creds_with_access_token_and_refresh_token["refresh_token"],token_uri="https://oauth2.googleapis.com/token",client_id=client_id,client_secret=client_secret)
        http = transport.requests.AuthorizedSession(credentials=creds)
        try:    
            service = build('gmail', 'v1', credentials=http)
            results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
            messages = results.get('messages', [])
            print(messages)
        except Exception as e:
            print(f"Error {e}")
    def get_body_content(self, parts):
           for part in parts:
               if part['mimeType'] == 'text/plain':
                   data = part['body']['data']
                   d=base64.urlsafe_b64decode(data).decode()
                   return base64.urlsafe_b64decode(data).decode()
               elif part['mimeType'] == 'multipart/mixed' or 'multipart/alternative':
                   return self.get_body_content(part['parts'])
           return ''
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
        # print(response.text)

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

        # except Exception as e:
        #     print(f"Error retrieving Gmail data: {e}")
        #     return Response({'error': 'Failed to retrieve Gmail data'}, status=500)
        # print("in viewwwwww")
        # return Response("login",status=200)

    def post(self,request):
        print("called")
        try:
            # SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
            data=request.body
            data_string = data.decode('utf-8')
            auth_credentials = json.loads(data_string)
            # print(auth_credentials["code"])
            
            url = "https://oauth2.googleapis.com/token"

            payload = {
                "grant_type": "authorization_code",
                "client_id": "189496678458-lbsabcd97iss894bi6c5tjmnrv1e3vh8.apps.googleusercontent.com",
                "client_secret": "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",
                "redirect_uri": "http://127.0.0.1",
                "code": "4/0AeaYSHD_1putU1S_wNFQQlJEs_QPzl8VmJbI5Woo6AX4qzp-EEl2eVYHIj5GsbFLGC7A-w"
            }

            headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
            }

            response = customRequest.request("POST", url, headers=headers, data=payload)
            # print(response.text)

            credentials=json.loads(response.text)
            # credential=response.text
            # print("========credential========",credentials)
            # print("===credential[access_token]====",credentials["access_token"])
            credentials = Credentials(token=credentials["access_token"])
            print(credentials)
            gmail_service = build('gmail', 'v1', credentials=credentials)
            # print(gmail_service)




            # In react if you have used GoogleLogin component then only
            # self.verify_auth(auth_credentials["credential"])
            # another way to redirect authorization url
            # res=self.auth("")
            # return
            #In react if you have used useGoogleLogin hook 
            # token_url = "https://oauth2.googleapis.com/token"
            # token_url="https://accounts.google.com/o/oauth2/auth"
            # payload = {
            #     "grant_type": "authorization_code",
            #     "client_id": "189496678458-qimsru4vsjae5tvfisn17gp7nh0v527k.apps.googleusercontent.com",
            #     "client_secret": "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",
            #     "redirect_uri": "http://127.0.0.1:8000/api/google-auth-verify",
            #     "code": auth_credentials["code"] 
            # }
            # print('-----auth_credentials["code"]--------', auth_credentials["code"])
            # return Response("login successfully",status=200)
            # payload = {
            #     "grant_type": "authorization_code",
            #     "client_id": "189496678458-lbsabcd97iss894bi6c5tjmnrv1e3vh8.apps.googleusercontent.com",
            #     "client_secret": "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",
            #     "redirect_uri": "http://127.0.0.1",
            #     "code": auth_credentials["code"] ,
            #     "scope":"https://www.googleapis.com/auth/gmail.readonly",
            #     "include_granted_scopes":"true",
            #     "access_type":"offline",
            #     "state":"Za1LLGyenbWEQ0o4oM4bOaLyDopOtw"
            # }
            # headers = {"Content-Type": "application/x-www-form-urlencoded"}
            # response = customRequest.post(token_url, data=payload, headers=headers)
            # print(response.text)

            #If you have Access Token and refresh token
            # self.gmail_access_using_access_refresh_token()
            #auth with python
            # self.auth_with_python()
            return Response("login",status=200)
            # pass
        except Exception as e:
            return Response(f"Error {e}",status=400)

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
