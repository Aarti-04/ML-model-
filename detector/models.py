from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from .managers import CustomUserManager,TokenManager
from django.conf import settings
from django.utils import timezone
import uuid

class CustomUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username=None
    email=models.EmailField(_("Email Address"),unique=True)
    USERNAME_FIELD="email"
    name=models.CharField(max_length=100,default="")
    updated_at=models.DateTimeField(auto_now=True)
    is_first_login=models.BooleanField(default=True)
    REQUIRED_FIELDS=[]
    objects=CustomUserManager()
class TokenModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    userid=models.ForeignKey(CustomUser,on_delete=models.CASCADE)
    jwt_refresh_token = models.TextField(default="")
    google_access_token=models.TextField(default="")
    google_refresh_token=models.TextField(default="")
    objects=models.Manager()
    token_manager=TokenManager()
class EmailMessageModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    userid=models.ForeignKey(CustomUser,on_delete=models.CASCADE)
    message_id=models.CharField(default=None,unique=True)
    header=models.CharField(max_length=255,default="")
    body=models.TextField(default="",blank=True)
    date=models.DateTimeField()
    sender=models.CharField(max_length=255,default="")
    recipient=models.CharField(default="")
    snippet=models.TextField(default="")
    spam=models.BooleanField(default=False)
    is_archived=models.BooleanField(default=False)
    is_deleted=models.BooleanField(default=False,blank=True)
    objects=models.Manager()





# # Create your models here.
