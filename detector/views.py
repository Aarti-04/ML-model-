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
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2 import id_token
from google.auth.transport import requests
from google.auth.exceptions import GoogleAuthError
import googleapiclient.discovery
from google.oauth2 import credentials
from google.oauth2 import service_account
from googleapiclient.discovery import build
import requests as customRequest
# Create your views here.
class GoogleAuthVerify(APIView):
    
    def post(self,request):
        print(request)
        try:
            SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
            # token = request.headers["Authorization"].split()[1]
            data=request.body
            data_string = data.decode('utf-8')
            # Parse the string as JSON
            credentials = json.loads(data_string)
            # print(credentials)
            print(credentials["code"])
            request = requests.Request()
            id_info = id_token.verify_oauth2_token(credentials["code"], request, '189496678458-qimsru4vsjae5tvfisn17gp7nh0v527k.apps.googleusercontent.com')
            print(id_info)
            data = {
                'code': credentials["code"],
                'client_id': "189496678458-qimsru4vsjae5tvfisn17gp7nh0v527k.apps.googleusercontent.com",
                'client_secret': "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",
                'redirect_uri': "http://localhost:8000",
                'grant_type': 'authorization_code',
                "prompt":"consent"
            }
            print(data)
            # response = customRequest.post('https://oauth2.googleapis.com/token',data=data)
            # print(response)
            credentials = service_account.Credentials.from_service_account_file('client_credential1.json')
            service = build('gmail', 'v1', credentials=credentials)
            # print(service)
            # results = service.users().messages().list(userId='me').execute()
            # print(result)
           
            # print(id_info["email"])
            return Response("login successfully",status=200)
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
