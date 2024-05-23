from django.urls import path
from .views import Predict,Train,SpamMailFeedback

urlpatterns = [
    # path("admin/", admin.site.urls),
    path("predict/",Predict.as_view(),name="predict"),
    # path("predict/",views.Predict.as_view(),name="predict"),
    # path("register/",RegisterAuthVerify.as_view(),name="register"),
    path("train/",Train.as_view(),name="train"),
    path("feedback/",SpamMailFeedback.as_view(),name="feedback")
    # path("google-auth-verify/",GoogleAuthVerify.as_view(),name="googleAuth"),
]