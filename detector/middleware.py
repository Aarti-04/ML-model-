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
