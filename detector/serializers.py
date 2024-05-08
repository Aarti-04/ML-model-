from typing import Any, Dict
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import Token
from .models import CustomUser,TokenModel
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.password_validation import validate_password

class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model=TokenModel
        fields="__all__"
class CustomeUserSerializer(serializers.ModelSerializer):
    # password = serializers.CharField(write_only=True)
    # def validate_password(self,value):
    #     validate_password(value)
    #     print("value",value)
    #     return value
    def validate(self, data):
        email = data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise serializers.ValidationError("This email is already registered.")
        return data
    # def create(self, validated_data):
    #     password = validated_data.pop('password', None)
    #     user = super().create(validated_data)
    #     print("user",user)
    #     if password:
    #         user.set_password(password)
    #         print("saved")
    #     user.save()
    #     return user
    class Meta:
        model=CustomUser
        exclude=["password"]


class EmailSerializer(serializers.Serializer):
    id = serializers.CharField()
    header = serializers.CharField()
    body = serializers.CharField()
    date = serializers.CharField()
    sender = serializers.CharField()
    spam = serializers.BooleanField()