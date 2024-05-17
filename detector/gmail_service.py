from .models import TokenModel
from rest_framework.views import APIView,Response,status
import os
from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from google.auth.transport import requests
from googleapiclient.discovery import build

load_dotenv()

def get_gmail_service(user):
    User_Token_cred=TokenModel.objects.get(userid=user.id)
    if(User_Token_cred):
        access_token=User_Token_cred.google_access_token
        refresh_token=User_Token_cred.google_refresh_token
    else:
        return Response("Please login with google")
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
    return service
