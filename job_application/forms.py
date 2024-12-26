from django import forms
from .models import JobApplication

class JobApplicationForm(forms.ModelForm):
    class Meta:
        model = JobApplication
        fields = ['full_name', 'email', 'phone_number', 'job_category', 'cv_cover_letter', 'privacy_agreement']
