# from typing import Union
# from django.contrib.auth.backends import BaseBackend
# from django.contrib.auth.base_user import AbstractBaseUser
# from .models import CustomUser
# # from django.contrib.auth.models import User
# class CustomAuthBackend(BaseBackend):
#     def get_user(self, email: int) -> Union[AbstractBaseUser,None]:
#         return super().get_user(email)
#     def authenticate(self, request,password=None,email=None,**args):
#         print("in CustomAuthBackend")
#         user = CustomUser.objects.filter(email=email).first()
#         print(user)
#         if user is None:
#             return None
#         if user.check_password(password):
#             return user
#         else:
#             print("in else")
#             return None

# from django.contrib.auth.backends import BaseBackend
# from django.contrib.auth import get_user_model

# CustomUser = get_user_model()

# class CustomAuthBackend(BaseBackend):
#     def get_user(self, email):
#         print("in get user",CustomUser.objects.filter(email=email).first())
#         return CustomUser.objects.filter(email=email).first()

#     def authenticate(self, request, email=None, password=None, **kwargs):
#         print("in CustomAuthBackend")
#         user = self.get_user(email)
#         print("User from database:", user)
#         if user is None:
#             return None
#         if user.check_password(password):
#             print("Password matched")
#             return user
#         else:
#             print("Password does not match")
#             return None