from rest_framework import generics, permissions, status
from rest_framework.response import Response
from .models import JobApplication
from .serializers import JobApplicationSerializer
from sib_api_v3_sdk import Configuration, ApiClient, SendSmtpEmail
from sib_api_v3_sdk.api.transactional_emails_api import TransactionalEmailsApi
from django.conf import settings
from sib_api_v3_sdk.rest import ApiException
from rest_framework.exceptions import ValidationError
import os
from rest_framework import serializers

class ApplyToJobView(generics.CreateAPIView):
    queryset = JobApplication.objects.all()
    serializer_class = JobApplicationSerializer
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
            job_application = self.perform_create(serializer)
            
            return Response({
                "success": True,
                "message": "Application submitted successfully",
                "application": serializer.data
            }, status=status.HTTP_201_CREATED)
            
        except serializers.ValidationError as e:
            error_message = str(e.detail)
            if "You have already submitted an application for this position" in error_message:
                return Response({
                    "success": False,
                    "message": "Duplicate application",
                    "error": "You have already submitted an application for this position.",
                    "error_code": "DUPLICATE_APPLICATION"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({
                "success": False,
                "message": "You have already submitted an application for this position",
                "error": self._format_errors(e.detail)
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            return Response({
                "success": False,
                "message": "An unexpected error occurred",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def perform_create(self, serializer):
        job_application = serializer.save()
        self._send_confirmation_email(job_application)
        return job_application

    def _send_confirmation_email(self, job_application):
        """Send confirmation email using Brevo (formerly Sendinblue)"""
        try:
            # Configure Brevo API client
            configuration = Configuration()
            configuration.api_key['api-key'] = os.getenv('BREVO_API_KEY')
            api_instance = TransactionalEmailsApi(ApiClient(configuration))

            # Prepare email content
            email_content = self._get_email_template(job_application)
            
            # Create email object
            email = SendSmtpEmail(
                to=[{"email": job_application.email}],
                sender={"name": "Your Company", "email": settings.DEFAULT_FROM_EMAIL},
                subject="Application Received - Next Steps",
                html_content=email_content
            )

            # Send email
            api_instance.send_transac_email(email)
            
        except ApiException as e:
            # Log the error but don't fail the application submission
            print(f"Failed to send confirmation email: {e}")

    def _get_email_template(self, application):
        """Generate HTML email content"""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2>Application Received</h2>
            <p>Dear {application.first_name} {application.last_name},</p>
            
            <p>Thank you for applying for the <strong>{application.job_title}</strong> position 
            (Ref: {application.job_reference_number}).</p>
            
            <p>What happens next:</p>
            <ul>
                <li>Our hiring team will review your application</li>
                <li>We aim to respond within 5 business days</li>
                <li>If your profile matches our requirements, we'll invite you for an interview</li>
            </ul>
            
            <p>Best regards,<br>
            Hiring Team</p>
        </body>
        </html>
        """

    def _format_errors(self, errors):
        """Convert DRF error format to a more user-friendly structure"""
        if isinstance(errors, str):
            return [errors]
        elif isinstance(errors, list):
            return errors
        elif isinstance(errors, dict):
            return [f"{field}: {', '.join(error)}" for field, error in errors.items()]
        return ["An unknown error occurred"]
                
class JobApplicationDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = JobApplication.objects.all()
    serializer_class = JobApplicationSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        original_status = instance.status
        
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        
        if not serializer.is_valid():
            print("Validation Errors:", serializer.errors)  # Debugging
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        updated_instance = serializer.save()
        
        # Check if status was changed to REJECTED
        if original_status != 'REJECTED' and updated_instance.status == 'REJECTED':
            self._send_rejection_email(updated_instance)
            
        return Response(serializer.data, status=status.HTTP_200_OK)

    def _send_rejection_email(self, job_application):
        """Send rejection email using Brevo (formerly Sendinblue)"""
        try:
            # Configure Brevo API client
            configuration = Configuration()
            configuration.api_key['api-key'] = os.getenv('BREVO_API_KEY')
            api_instance = TransactionalEmailsApi(ApiClient(configuration))

            # Prepare email content
            email_content = self._get_rejection_email_template(job_application)
            
            # Create email object
            email = SendSmtpEmail(
                to=[{"email": job_application.email}],
                sender={"name": "Your Company", "email": settings.DEFAULT_FROM_EMAIL},
                subject=f"Update on Your Application for {job_application.job_title}",
                html_content=email_content
            )

            # Send email
            api_instance.send_transac_email(email)
            
        except ApiException as e:
            # Log the error but don't fail the status update
            print(f"Failed to send rejection email: {e}")
    
    def _get_rejection_email_template(self, application):
        """Generate HTML rejection email content"""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <p>Dear {application.first_name} {application.last_name},</p>
            
            <p>Thank you for your interest in the <strong>{application.job_title}</strong> position 
            (Ref: {application.job_reference_number}) and for taking the time to go through our application process.</p>
            
            <p>After careful consideration of all applications received, we regret to inform you that we will not be 
            moving forward with your candidacy at this time. We received many qualified applications, making this 
            a difficult decision.</p>
            
            <p>Please note that this decision is not necessarily a reflection of your qualifications or experience. 
            We encourage you to apply for future openings that match your skills and interests.</p>
            
            <p>We appreciate your understanding and wish you success in your job search and future professional endeavors.</p>
            
            <p>Best regards,<br>
            Hiring Team</p>
        </body>
        </html>
        """

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

class JobApplicationListView(generics.ListAPIView):
    serializer_class = JobApplicationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return JobApplication.objects.all()