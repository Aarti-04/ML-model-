from django.contrib import admin
from django.urls import path
from .views import Predict

urlpatterns = [
    path("admin/", admin.site.urls),
    path("predict/",Predict.as_view(),name="predict")

]
