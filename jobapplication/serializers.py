from rest_framework import serializers
from .models import JobApplication

class JobApplicationSerializer(serializers.ModelSerializer):
    

    class Meta:
        model = JobApplication
        fields = '__all__'  # Corrected the syntax for including all fields
        read_only_fields = ['status', 'applied_at']  # Corrected the syntax for read-only fields