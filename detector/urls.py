from django.contrib import admin
from django.urls import path
from .views import Predict,GoogleAuthVerify,RegisterAuthVerify,MailRead,ComposeMail,TokenRefresh,RegisterWithToken,LoginUser

urlpatterns = [
    # path("admin/", admin.site.urls),
    path("predict/",Predict.as_view(),name="predict"),
    path("register/",RegisterAuthVerify.as_view(),name="register"),
    path("google-auth-callback/",RegisterWithToken.as_view(),name="register1"),
    path("login/",LoginUser.as_view(),name="login"),
    path("google-auth-verify/",GoogleAuthVerify.as_view(),name="googleAuth"),
    # path("mailoperation",MailOperation.as_view(),name="MailOperation"),
    path("mailread/",MailRead.as_view(),name="mailread"),
    path("composemail/",ComposeMail.as_view(),name="ComposeMail"),
    path("refreshtoken/",TokenRefresh.as_view(),name="refreshtoken")
    


]
