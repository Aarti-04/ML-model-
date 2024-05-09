import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

CLIENT_SECRET_FILE = 'client_secret.json'
API_NAME = 'gmail'
API_VERSION = 'v1'
SCOPES = ['https://mail.google.com/']

service = Create_Service(CLIENT_SECRET_FILE, API_NAME, API_VERSION, SCOPES)

emailMsg = 'You won $100,000'
mimeMessage = MIMEMultipart()
mimeMessage['to'] = '<Receipient>@gmail.com'
mimeMessage['subject'] = 'You won'
mimeMessage.attach(MIMEText(emailMsg, 'plain'))
raw_string = base64.urlsafe_b64encode(mimeMessage.as_bytes()).decode()

message = service.users().messages().send(userId='me', body={'raw': raw_string}).execute()
print(message)

from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from google.auth.transport.requests import Request
from google.auth.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.exceptions import RefreshError
from googleapiclient.errors import HttpError
import base64
import os


def fetch_emails_sequentially(service, query, max_results=10):
    try:
        messages = []
        page_token = None
        while True:
            response = service.users().messages().list(userId='me', q=query, maxResults=max_results, pageToken=page_token).execute()
            messages.extend(response.get('messages', []))
            page_token = response.get('nextPageToken')
            if not page_token:
                break
        return messages
    except HttpError as e:
        print(f"Error fetching emails: {e}")
        return []

service = build('gmail', 'v1', credentials=creds)

# Fetch emails sequentially with pagination
query = 'label:inbox'
emails = fetch_emails_sequentially(service, query)

# Process fetched emails as needed
for email in emails:
    print(email['id'])
class MailRead(APIView):
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination 

    def get_body_content(self, parts):
        """Extract text or HTML content from email parts."""
        if not parts:
            return ''
        for part in parts:
            if part.get('mimeType') in ['text/plain', 'text/html']:
                data = part['body']['data']
                return base64.urlsafe_b64decode(data).decode()
            elif part.get('mimeType') in ['multipart/mixed', 'multipart/alternative']:
                return self.get_body_content(part.get('parts', []))
        return ''

    def fetch_emails(self, service, query, max_results=30):
    """Fetch emails sequentially."""
    try:
        results = []
        page_token = None
        while True:
            response = service.users().messages().list(userId='me', q=query, maxResults=max_results, pageToken=page_token).execute()
            messages = response.get('messages', [])
            
            for message in messages:
                msg_id = message['id']
                full_message = service.users().messages().get(userId='me', id=msg_id).execute()
                payload = full_message['payload']
                headers = payload['headers']
                # sender = next((header['value'] for header in headers if header['name'] == 'From'), None)
                # subject = next((header['value'] for header in headers if header['name'] == 'Subject'), None)
                # date = next((header['value'] for header in headers if header['name'] == 'Date'), None)
                sender = header['value'] for header in headers: if header['name'] == 'From')
                subject = next((header['value'] for header in headers if header['name'] == 'Subject'), None)
                date = next((header['value'] for header in headers if header['name'] == 'Date'), None)
                parts = payload.get('parts', [])
                body = self.get_body_content(parts)
                # Post the body to prediction API
                predict_response = customRequest.post('http://127.0.0.1:8000/api/predict/', body)
                prediction_data = predict_response.json()
                spamOrNot = prediction_data["prediction"] == "spam"
                results.append({'id': msg_id, 'header': subject, 'body': body, "date": date, 'sender': sender, "spam": spamOrNot})

            # Check if there are more messages to fetch
            if 'nextPageToken' in response:
                page_token = response['nextPageToken']
            else:
                break

        return results
    except HttpError as e:
        print(f"Error fetching emails: {e}")
        return []

    def get(self, request):
        """Handle GET request."""
        lable_query = request.GET.get("querylable")
        message_limit = request.GET.get("msglimit")

        # Fetch user token credentials
        User_Token_cred = TokenModel.objects.get(userid=request.user.id)
        if not User_Token_cred:
            return Response("Please login with Google", status=status.HTTP_401_UNAUTHORIZED)
        
        access_token = User_Token_cred.google_access_token
        refresh_token = User_Token_cred.google_refresh_token
        CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
        CLIENT_ID = os.environ.get("CLIENT_ID")

        credentials = Credentials(token=access_token, token_uri=os.environ.get("ToKEN_URI"), refresh_token=refresh_token, client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
        
        # Check if the credentials are expired and refresh if needed
        if credentials.expired:
            try:
                credentials.refresh(Request())
            except RefreshError as e:
                return Response({"error": "Failed to refresh token."}, status=status.HTTP_401_UNAUTHORIZED)
                
        service = build('gmail', 'v1', credentials=credentials)
        query = f'label:{lable_query}'
        results = self.fetch_emails(service, query, max_results=int(message_limit))

        page_size = self.request.query_params.get('page_size', 10) 
        paginator = self.pagination_class()
        paginator.page_size = page_size
        paginated_results = paginator.paginate_queryset(results, request)
        
        email_serializer = EmailSerializer(paginated_results, many=True)
        return paginator.get_paginated_response({"data": email_serializer.data})
