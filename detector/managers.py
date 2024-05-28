from typing import Any
from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.db import models
from django.db.models import Q
# from .models import TokenModel
class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """
    def create_user(self, email, password, **extra_fields):
        """
        Create and save a user with the given email and password.
        """
        if not email:
            raise ValueError(_("The Email must be set"))
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))
        return self.create_user(email, password, **extra_fields)

class TokenManager(models.Manager):
    def update_jwt_token(self,access_token):
        user_credentials=self.model(jwt_access_token=access_token)
        return user_credentials.save()
class EmailManager(models.Manager):
    def filter_Email(self,sender="",recipient="",orderby="date"):
        return super().get_queryset().filter(Q(recipient__icontains=recipient)&Q(sender__icontains=sender)&Q(is_deleted=False)&Q(is_archived=False)&Q(spam=False)).order_by(orderby).all()



