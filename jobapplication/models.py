from django.db import models
from jobposting.models import JobPost

class JobApplication(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('SHORTLISTED', 'Shortlisted'),
        ('REJECTED', 'Rejected'),
        ('HIRED', 'Hired'),
    ]

    EDUCATIONAL_LEVEL_CHOICES = [
        ('HIGH_SCHOOL', 'High School'),
        ('ASSOCIATE', 'Associate Degree'),
        ('BACHELOR', "Bachelor's Degree"),
        ('MASTER', "Master's Degree"),
        ('PHD', 'PhD'),
    ]

    job_post = models.ForeignKey(
        JobPost,
        on_delete=models.CASCADE,
        related_name="applications"
    )
    resume = models.FileField(upload_to="resumes/")
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='PENDING'
    )
    applied_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    job_title = models.CharField(max_length=200, blank=True, null=True)
    job_reference_number = models.CharField(max_length=8, blank=True, null=True)

    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=254)

    educational_level = models.CharField(
        max_length=20,
        choices=EDUCATIONAL_LEVEL_CHOICES,
        default='HIGH_SCHOOL'
    )

    class Meta:
        ordering = ['-applied_at']
        verbose_name = 'Job Application'
        verbose_name_plural = 'Job Applications'
        unique_together = ['job_post', 'email']

    def __str__(self):
        return f"{self.email} - {self.job_post.title}"

    def save(self, *args, **kwargs):
        if not self.job_title:
            self.job_title = self.job_post.title
        if not self.job_reference_number:
            self.job_reference_number = self.job_post.reference_number
        super().save(*args, **kwargs)