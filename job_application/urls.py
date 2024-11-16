from django.urls import path
from . import views

urlpatterns = [
    path('job_application/', views.job_application, name='job_application'),
    path('job_application/<int:pk>/', views.job_application_detail, name='job_application_detail'),
]
