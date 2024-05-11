from django.contrib import admin
from django.urls import path
from .views import MailFromDb,GoogleLoginView,Logout,Predict,GoogleRegisterView,MailRead,ComposeMail,TokenRefresh,LoginUser

urlpatterns = [
    # path("admin/", admin.site.urls),
    path("predict/",Predict.as_view(),name="predict"),
    # path("register/",RegisterAuthVerify.as_view(),name="register"),
    path("googleregister/",GoogleRegisterView.as_view(),name="GoogleRegisterView"),
    path("googlelogin/",GoogleLoginView.as_view(),name="googlelogin"),
    path("login/",LoginUser.as_view(),name="login"),
    path("logout/",Logout.as_view(),name="logout"),
    # path("google-auth-verify/",GoogleAuthVerify.as_view(),name="googleAuth"),
    # path("mailoperation",MailOperation.as_view(),name="MailOperation"),
    path("mailread/",MailRead.as_view(),name="mailread"),
    path("mailreadfromdb/",MailFromDb.as_view(),name="mailfromdb"),
    path("composemail/",ComposeMail.as_view(),name="ComposeMail"),
    path("refreshtoken/",TokenRefresh.as_view(),name="refreshtoken")
    


]
