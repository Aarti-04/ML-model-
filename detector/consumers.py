# # from channels.generic.websocket import AsyncWebsocketConsumer,WebsocketConsumer
# # # # import json
# # # # from channels.generic.websocket import WebsocketConsumer
# # # import json
# # class PracticeConsumer(AsyncWebsocketConsumer):
# #     async def connect(self):
# #            await self.accept()
# #     async def disconnect(self, code):
# #         pass
# #     async def receive(self, text_data=None, bytes_data=None, **kwargs):
# #         print("hello")
# #         self.send("hello world")
# #         if text_data == 'PING':
# #              print("in ping")
# #              await self.send('hello')
# # # class demoConsumer(WebsocketConsumer):
# # #      def connect(self):
# # #            self.accept()
# # #            self.send(text_data=json.dumps({'type':'connection_established','message':'you are now connected'}))
# # # # class ChatConsumer(WebsocketConsumer):
# # # #     def connect(self):
# # # #         self.accept()
# # # #     def disconnect(self, close_code):
# # # #         pass
# # # #     def receive(self, text_data):
# # # #         text_data_json = json.loads(text_data)
# # # #         message = text_data_json['message']
# # # #         self.send(text_data=json.dumps({
# # # #             'message': message
# # # #         }))


# # # # myapp/consumers.py

# # # # from channels.generic.websocket import AsyncWebsocketConsumer

# # # # class MyConsumer(AsyncWebsocketConsumer):
# # # #     async def connect(self):
# # # #         await self.accept()

# # # #     async def disconnect(self, close_code):
# # # #         pass

# # # #     async def receive(self, text_data):
# # # #         # Handle received data here
# # # #         pass

# from channels.generic.websocket import AsyncWebsocketConsumer
# import requests as customRequest
# from .views import MailRead
# from asgiref.sync import sync_to_async
# import asyncio
# from urllib.parse import parse_qs
# import os
# from google.oauth2.credentials import Credentials
# from google.auth.transport import requests
# from googleapiclient.discovery import build
# class MyConsumer(AsyncWebsocketConsumer):
#     async def connect(self):
#         await self.accept()
#         # await self.start_reading_mail()
#         print("WebSocket connection established.")
#         # print("WebSocket kwargs",self.scope["url_route"])
#         query_params = self.scope["query_string"].decode()
#         parsed_query_params = parse_qs(query_params)
#         access_token = parsed_query_params.get("access_token", [None])[0]
#         print(access_token)
        
#         try:
#             tokens_response=self.fetch_tokens(access_token)
#             print(tokens_response.text)
#         except Exception as e:
#             print(str(e))
        
#     def fetch_tokens(self,access_token):
#         # Make a GET request to your API to fetch tokens
#         # Example URL for your API endpoint
#         api_url = 'http://127.0.0.1:8000/api/Mailreadtoken/'
#         headers = {
#             "Authorization": f"Bearer {access_token}"
#         }
#         response = customRequest.get(api_url, headers=headers)
#         return response
#     async def start_reading_mail(self):
#         while True:
#             await self.fetch_and_insert_emails()
#             await asyncio.sleep(60) #for 60 seconds 
#     def initialize_gmail_service(self, access_token, refresh_token):
#         CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
#         CLIENT_ID = os.environ.get("CLIENT_ID")
        
#         # Create credentials object
#         credentials = Credentials(
#             token=access_token,
#             token_uri=os.environ.get("ToKEN_URI"),
#             refresh_token=refresh_token,
#             client_id=CLIENT_ID,
#             client_secret=CLIENT_SECRET
#         )

#         # Check if the credentials are expired
#         if credentials.expired:
#             # Refresh the token
#             request = requests.Request()
#             credentials.refresh(request)

#         # Build the Gmail service
#         service = build('gmail', 'v1', credentials=credentials)
#         return service

#     @sync_to_async
#     def fetch_and_insert_emails(self):
#         mail_reader=MailRead()

#     async def disconnect(self, close_code):
#         print("WebSocket connection closed.")

#     async def receive(self, text_data):
#         print("Received message:", text_data)


from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from asgiref.sync import sync_to_async
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from datetime import datetime
import base64
import re
import httpx
import asyncio
from .models import TokenModel,EmailMessageModel,CustomUser
from .serializers import EmailSerializer
EMAIL_PATTERN = re.compile(r'<([^<>]+)>')
import os
import jwt
from urllib.parse import parse_qs
from google.auth.transport import requests

class MyConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        query_params = self.scope["query_string"].decode()
        parsed_query_params = parse_qs(query_params)
        access_token = parsed_query_params.get("access_token", [None])[0]
        print("called start_reading_mail")
        await self.start_reading_mail(access_token)
    async def disconnect(self, close_code):
        print("WebSocket disconnected")
        await self.close()
    async def start_reading_mail(self,access_token):
        while True:
            await self.read_and_insert_mail(access_token)
            print("Record inserted")
            await asyncio.sleep(60)  # Wait for 1 minute before repeating

    async def read_and_insert_mail(self,access_token):
        try:
            # Get the user's credentials from the database
            user_token_cred = await self.get_user_credentials(access_token)

            # Check if credentials exist
            if user_token_cred:
                access_token = user_token_cred.google_access_token
                refresh_token = user_token_cred.google_refresh_token
            else:
                return  # Handle case where credentials are not found

            # Build the Gmail service
            service = await self.build_gmail_service(access_token, refresh_token)
            print("service",service)
            # Fetch emails and insert into database
            results = await self.fetch_emails(service, "",user_token_cred)
            print("results",results[0]["user_id"])
            print("results",results[0]["message_id"])
            
            await self.save_mail_data(results)

        except Exception as e:
            print(f"Error reading and inserting mail: {e}")

    @sync_to_async
    def get_user_credentials(self,access_token):
        # Fetch user credentials from the database
        # print("self scope",self.scope)
        # access_token = self.scope["url_route"]["kwargs"]["access_token"]
        print("access token",access_token)
        decoded_token = jwt.decode(access_token, os.environ.get("SECRET_KEY"), algorithms=['HS256'])
        print(decoded_token)
        # Extract the user ID from the decoded token
        user_id = decoded_token['user_id']
        print("decoded user id",user_id)
        Token_obj=TokenModel.objects.filter(userid=user_id).first()
        print("Token_obj",Token_obj)
        return TokenModel.objects.filter(userid=user_id).first()

    @database_sync_to_async
    def save_mail_data(self, mail_data):
        # Save mail data into the database
        # print("in save mail data")
        try:
            for mail in mail_data:
                exist_mail = EmailMessageModel.objects.filter(message_id=mail["message_id"]).exists()
                
                if not exist_mail:
                    # print("mail.....",mail)
                    # return
                    processed_data = self.extract_email_info(mail)
                    # print("processed_data",processed_data)
                    # return
                    serialized_email = EmailSerializer(data=processed_data)
                    if serialized_email.is_valid(raise_exception=True):
                        serialized_email.save()
                        print("data saved.....")
                else:
                    print("in else")
                    break

        except Exception as e:
            print(str(e))

    # @database_sync_to_async
    def extract_email_info(self, data):
        # Extract and process email information
        # print("data.......",data)
        # return
        processed_mail_data = data
        processed_mail_data["date"] = datetime.strptime(data["date"].replace(' (UTC)', ''), '%a, %d %b %Y %H:%M:%S %z')
        recipient_email_matched = re.search(EMAIL_PATTERN, data["recipient"])
        processed_mail_data["recipient"] = recipient_email_matched.group(1) if recipient_email_matched else data["recipient"].strip()
        sender_email_matched = re.search(EMAIL_PATTERN, data["sender"])
        processed_mail_data["sender"] = sender_email_matched.group(1) if sender_email_matched else data["sender"].strip()
        # print("processed_mail_data",processed_mail_data)
        return processed_mail_data

    @sync_to_async
    def build_gmail_service(self, access_token, refresh_token):
        # Build the Gmail service with credentials
        CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
        CLIENT_ID = os.environ.get("CLIENT_ID")
        credentials = Credentials(
            token=access_token,
            token_uri=os.environ.get("TOKEN_URI"),
            refresh_token=refresh_token,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET
        )
        # print("credentials",credentials)
        if credentials.expired:
            request = requests.Request()
            credentials.refresh(request)

        return build('gmail', 'v1', credentials=credentials)
    @sync_to_async
    def fetch_emails(self, service, query,user_token_cred):
        # Fetch emails from Gmail
        try:
            user_object=CustomUser.objects.get(email=user_token_cred.userid)
            if(user_object.is_first_login):
                max_results=50
            else:
                max_results=10
            print("max_results",max_results)
            response = service.users().messages().list(userId='me', q=query, maxResults=max_results).execute()
            messages = response.get('messages', [])
            if(messages):
                print("messages found")
            else:
                print("No messages found.")
            results = []
            for message in messages[:max_results]:
                user_id=user_object.id
                msg_id = message['id']
                full_message = service.users().messages().get(userId='me', id=msg_id).execute()
                payload = full_message['payload']
                headers = payload['headers']
                snippet = full_message["snippet"]
                sender = next((header['value'] for header in headers if header['name'] == 'From'), None)
                to = next((header['value'] for header in headers if header['name'] == 'To'), None)
                subject = next((header['value'] for header in headers if header['name'] == 'Subject'), None)
                date = next((header['value'] for header in headers if header['name'] == 'Date'), None)
                parts = payload.get('parts', [])
                # print("payload parts...",parts)
                body = self.get_body_content(parts)
                # body="<p>Hello good morning</p>"
                print("first body")
                if body=='':
                    body=self.get_body_content(parts,second_time=True)
                    print("second time read")
                    print("second body",body)

                # Predict if the email is spam or not
                # prediction_data = await self.predict_spam(body)
                # spam_or_not = True if (prediction_data["prediction"] == "spam") else False

                results.append({'snippet': snippet, 'message_id': msg_id, 'header': subject, "body": body,
                                "date": date, 'sender': sender, "recipient": to, "spam": False,"user_id":user_id})

            return results
        except Exception as e:
            print(f"Error fetching emails: {e}")
    def get_body_content(self, parts,second_time=False):
        # print("parts......",parts)
        body=''
        if not parts:
            return body
        for part in parts:
            if second_time and part.get('mimeType') == 'text/plain':
                data1 = part['body']['data'] 
                if data1:
                    body+=base64.urlsafe_b64decode(data1).decode()
                    print("data1 returned")
            if part.get('mimeType') == 'text/html':
                data = part['body']['data']
                if data:
                    body+=base64.urlsafe_b64decode(data).decode()
                else:
                    body+=""
        # print("body data",body)
        return body
        # Predict if the email