from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('authapp.urls')),  # Include your app's URLs
    path('api/', include('Schoolapp.urls')),
    path('api/', include('Admissionapp.urls')),
    path('api/', include('job_application.urls')),  # Include job_application app's URLs
    path('api/', include('momo_pay.urls')),
    path('api/', include('hubtel.urls')),
    path('api/', include('Reservationapp.urls')),
    path('api/', include('tickets.urls')),
    path('api/', include('Subscriptions.urls')),
    path('api/', include('admin_auth.urls', namespace='admin_auth')),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)