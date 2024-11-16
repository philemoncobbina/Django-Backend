from django.db import models

class JobApplication(models.Model):
    full_name = models.CharField(max_length=300)
    email = models.EmailField()
    phone_number = models.CharField(max_length=20)
    job_category = models.CharField(max_length=500)
    cv_cover_letter = models.FileField(upload_to='cv_cover_letters/')
    privacy_agreement = models.BooleanField(default=False)

    def __str__(self):
        return self.full_name
