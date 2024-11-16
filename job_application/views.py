from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.core.mail import send_mail
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt  # Import csrf_exempt
from .forms import JobApplicationForm
from .models import JobApplication

@csrf_exempt  # Apply csrf_exempt decorator
def job_application(request):
    if request.method == 'GET':
        job_applications = JobApplication.objects.all()
        return JsonResponse({'job_applications': list(job_applications.values())})

    elif request.method == 'POST':
        form = JobApplicationForm(request.POST, request.FILES)
        if form.is_valid():
            job_application = form.save()
            send_application_confirmation_email(job_application)
            return JsonResponse({'message': 'Application submitted successfully'}, status=201)
        else:
            return JsonResponse({'errors': form.errors}, status=400)

@csrf_exempt  # Apply csrf_exempt decorator
def job_application_detail(request, pk):
    job_application = get_object_or_404(JobApplication, pk=pk)
    if request.method == 'GET':
        return JsonResponse({'job_application': job_application})

    elif request.method == 'DELETE':
        job_application.delete()
        return JsonResponse({'message': 'Job application deleted successfully'}, status=204)

def send_application_confirmation_email(job_application):
    subject = 'Application Submission Confirmation'
    message = f'Dear {job_application.full_name},\n\nThank you for submitting your application. Your CV/cover letter will be reviewed shortly.\n\nBest regards,\nThe Team'
    sender = settings.EMAIL_HOST_USER
    recipient = [job_application.email]
    send_mail(subject, message, sender, recipient)
