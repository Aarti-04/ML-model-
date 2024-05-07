from typing import Union
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.base_user import AbstractBaseUser
from .models import CustomUser
# from django.contrib.auth.models import User
class CustomAuthBackend(BaseBackend):
    def get_user(self, email: int) -> Union[AbstractBaseUser,None]:
        return super().get_user(email)
    def authenticate(self, request,password=None,email=None,**args):
        print("in CustomAuthBackend")
        user = CustomUser.objects.filter(email=email).first()
        print(user)
        if user is None:
            return None
        if user.check_password(password):
            return user
        else:
            print("in else")
            return None