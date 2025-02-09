from rest_framework import generics, permissions
from .models import JobApplication
from .serializers import JobApplicationSerializer

class ApplyToJobView(generics.CreateAPIView):
    queryset = JobApplication.objects.all()
    serializer_class = JobApplicationSerializer
    permission_classes = []  # Allow unauthenticated users

    def perform_create(self, serializer):
        # Save the job application without an applicant
        serializer.save()

class JobApplicationListView(generics.ListAPIView):
    queryset = JobApplication.objects.all()
    serializer_class = JobApplicationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return self.queryset.filter(applicant=self.request.user)