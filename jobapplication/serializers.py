# serializers.py
from rest_framework import serializers
from .models import JobApplication

class JobApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobApplication
        fields = '__all__'
        read_only_fields = ['applied_at']

    def validate(self, data):
        # Check if user already applied to this job
        if JobApplication.objects.filter(
            email=data.get('email'),
            job_post=data.get('job_post')
        ).exists():
            raise serializers.ValidationError(
                "You have already submitted an application for this position."
            )
        return data