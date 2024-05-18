# # middleware.py
# from rest_framework.response import Response
# from rest_framework.exceptions import ValidationError
# from .models import CustomUser
# import jwt
# import random
# import string
# import requests
# import json

# class TokenValidationMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         if request.method == 'POST' and request.path == '/api/register/':  # Adjust the path as per your registration endpoint
#             data=request.body
#             data_string = data.decode('utf-8')
#             auth_credentials = json.loads(data_string)
#             print("auth_credentials",auth_credentials)
#             print("middleware called")
#             if auth_credentials:
#                 id_token = auth_credentials["creds"]["id_token"]
#                 print("id token",id_token)
#                 if id_token:
#                     try:
#                         self.validate_token(id_token)
#                         print("validate called")
#                     except ValidationError as e:
#                         print("error",str(e))
#                         # response = self.get_response(request)
#                         # return response
#                         # return Response(str(e), status=400)

#         response = self.get_response(request)
#         return response

#     def validate_token(self, id_token):
#         r = requests.get(
#             "https://www.googleapis.com/oauth2/v3/tokeninfo",
#             params={"id_token": id_token}
#         )
#         r.raise_for_status()

#         data = r.json()
#         if CustomUser.objects.filter(email=data["email"]).exists():
#             print("Email already exist")
#             raise ValidationError("Email already exist")
#         print("data",data)
#         if "error_description" in data:
#             raise ValidationError(data["error_description"])
from django.http import JsonResponse
from rest_framework.response import Response
import re

class PredictRequestValidationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        print("middleware called")
        if request.path == '/api/composemail/' and request.method == 'POST':
            data = request.POST
            sender_email = data.get('recipient')
            header = data.get('header')
            body = data.get('body')

            # Check if sender_email, header, and body are not empty
            if not sender_email or not header or not body:
                print("error returned")
                return JsonResponse({'error': 'sender_email, header, and body are required.'})
            
            # Validate sender_email format
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, sender_email):
                return JsonResponse({'error': 'Invalid sender_email format.'})

        response = self.get_response(request)
        return response