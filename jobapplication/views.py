from rest_framework import generics, permissions, status
from rest_framework.response import Response
from .models import JobApplication
from .serializers import JobApplicationSerializer
from sib_api_v3_sdk import Configuration, ApiClient, SendSmtpEmail
from sib_api_v3_sdk.api.transactional_emails_api import TransactionalEmailsApi
from django.conf import settings
from sib_api_v3_sdk.rest import ApiException
import os

class ApplyToJobView(generics.CreateAPIView):
    queryset = JobApplication.objects.all()
    serializer_class = JobApplicationSerializer
    permission_classes = []  # Allow unauthenticated users
    
    def perform_create(self, serializer):
        # Save the job application
        job_application = serializer.save()
        
        # Send confirmation email to the applicant
        self.send_confirmation_email(job_application)
    
    def send_confirmation_email(self, job_application):
        """
        Sends a confirmation email to the applicant after successful job application.
        """
        configuration = Configuration()
        configuration.api_key['api-key'] = os.getenv('BREVO_API_KEY')
        
        api_instance = TransactionalEmailsApi(ApiClient(configuration))
        
        send_smtp_email = SendSmtpEmail(
            to=[{"email": job_application.email}],
            sender={"name": "Your Company", "email": settings.DEFAULT_FROM_EMAIL},
            subject="Your Job Application Confirmation",
            html_content=f"""
            <html>
            <body>
                <p>Dear {job_application.first_name} {job_application.last_name},</p>
                <p>Thank you for applying for the position of <strong>{job_application.job_title}</strong> (Reference Number: {job_application.job_reference_number}).</p>
                <p>We have received your application and it is currently under review. We will notify you of the status of your application once the review process is complete.</p>
                <p>Best regards,<br>Your Company</p>
            </body>
            </html>
            """
        )
        
        try:
            api_response = api_instance.send_transac_email(send_smtp_email)
            print("Email sent successfully: %s\n" % api_response)
        except ApiException as e:
            print("Exception when sending email: %s\n" % e)

class JobApplicationDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = JobApplication.objects.all()
    serializer_class = JobApplicationSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

class JobApplicationListView(generics.ListAPIView):
    serializer_class = JobApplicationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return JobApplication.objects.all()