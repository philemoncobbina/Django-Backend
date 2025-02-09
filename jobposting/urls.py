# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import JobPostViewSet

router = DefaultRouter()
router.register(r'jobposts', JobPostViewSet)

urlpatterns = [
    path('api/', include(router.urls)),
]