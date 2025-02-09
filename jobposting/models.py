from django.db import models
from django.utils import timezone
from django.db.models import Max
from authapp.models import CustomUser

class JobPost(models.Model):
    STATUS_CHOICES = [
        ('DRAFT', 'Draft'),
        ('SCHEDULED', 'Scheduled'),
        ('PUBLISHED', 'Published'),
    ]
    
    # Modified reference number field to allow null initially
    reference_number = models.CharField(
        max_length=8,
        unique=True,
        null=True,  # Allow null initially
        blank=True,  # Allow blank initially
        editable=False
    )
    
    title = models.CharField(max_length=200)
    description = models.TextField()
    requirements = models.TextField()
    location = models.CharField(max_length=100)
    salary_range = models.CharField(max_length=100)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='DRAFT'
    )
    
    # User relationship
    created_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="job_posts"
    )
    # New field to store user email
    created_by_email = models.EmailField(max_length=254, null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    scheduled_date = models.DateTimeField(null=True, blank=True)
    published_date = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Job Post'
        verbose_name_plural = 'Job Posts'
    
    def save(self, *args, **kwargs):
        if not self.reference_number:
            last_ref_num = JobPost.objects.all().aggregate(Max('reference_number'))['reference_number__max']
            if last_ref_num:
                try:
                    last_num = int(last_ref_num[2:])
                    new_num = last_num + 1
                except (ValueError, IndexError):
                    new_num = 1
            else:
                new_num = 1
            self.reference_number = f'RF{new_num:06d}'
        
        # Save creator's email
        if self.created_by and not self.created_by_email:
            self.created_by_email = self.created_by.email
            
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.reference_number or 'No Reference'} - {self.title}"
    
    def is_published(self):
        """Check if the job post is published"""
        return self.status == 'PUBLISHED'
    
    def is_scheduled(self):
        """Check if the job post is scheduled"""
        return self.status == 'SCHEDULED'
    
    def can_be_published(self):
        """Check if the job post can be published"""
        if self.status == 'SCHEDULED' and self.scheduled_date:
            return timezone.now() >= self.scheduled_date
        return self.status == 'DRAFT'