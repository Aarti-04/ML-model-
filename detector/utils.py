import random
from .models import CustomUser,TokenModel
import requests
import os
from dotenv import load_dotenv
load_dotenv()

def generate_random_password(email):
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        password_base = email.split('@')[0] + random_string
        return password_base
      
      
def saveCredentials(user_email="", google_access_token="",google_refresh_token="",jwt_refresh_token=""):
        user, created =CustomUser.objects.get_or_create(email=user_email)
        
        # Get or create a TokenModel instance for the user
        token_obj, _ = TokenModel.objects.get_or_create(userid=user)
        
        # Update the TokenModel instance with the access and refresh tokens
        token_obj.jwt_refresh_token=jwt_refresh_token
        token_obj.google_access_token=google_access_token
        token_obj.google_refresh_token = google_refresh_token
        print("token object",token_obj)
        token_obj.save()
        return token_obj
      
def get_user_info_from_google(token_info):
        google_access_token = token_info.get('access_token')
        google_refresh_token = token_info.get('refresh_token')  # Optional, depending on the scope
        user_info_url = f"https://www.googleapis.com/oauth2/v1/userinfo?access_token={google_access_token}"
        user_info_response = requests.get(user_info_url)
        if user_info_response.status_code == 200:
            user_info = user_info_response.json()
            print(user_info)
            # user_password=self.generate_random_password(user_info["email"])
            user={"email":user_info["email"],"name":user_info["name"]}
            return user
        else:
          return None
def get_google_access_token(google_refresh_token):
      token_uri = os.environ.get("ToKEN_URI")
      payload = {
          "refresh_token": google_refresh_token,
          "client_id": os.environ.get("CLIENT_ID"),
          "client_secret": os.environ.get("CLIENT_SECRET"),
          "grant_type": 'refresh_token',
      }

      # Make the POST request to get the access token
      response = requests.post(token_uri, data=payload)

      # Check if the request was successful
      if response.status_code == 200:
          # Parse the JSON response to get the access token
          access_token = response.json().get("access_token")
          print("access_token..",access_token)
          return access_token
      else:
        return None

