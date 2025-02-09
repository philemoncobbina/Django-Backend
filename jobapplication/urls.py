from django.urls import path
from .views import ApplyToJobView, JobApplicationListView

urlpatterns = [
    path('apply/', ApplyToJobView.as_view(), name='apply_to_job'),
    path('my-applications/', JobApplicationListView.as_view(), name='my_applications'),
]