from rest_framework import viewsets, status
from rest_framework.response import Response
from .models import Admission, AdmissionLog
from .serializers import AdmissionSerializer, AdmissionLogSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import action
from django.forms.models import model_to_dict
from django.db.models import Max


class AdmissionViewSet(viewsets.ModelViewSet):
    serializer_class = AdmissionSerializer

    def get_queryset(self):
        return Admission.objects.all()  # Default to all admissions for list action

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def my_admissions(self, request):
        """
        Fetch admissions for the authenticated user.
        """
        admissions = Admission.objects.filter(user=request.user)
        serializer = self.get_serializer(admissions, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def all_admissions(self, request):
        """
        Fetch all admissions for all users.
        """
        admissions = self.get_queryset()
        serializer = self.get_serializer(admissions, many=True)
        return Response(serializer.data)

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Generate a unique admission number
        admission_number = self.generate_admission_number()

        # Save the admission with the generated admission number
        admission = serializer.save(
            admission_number=admission_number,
            user=request.user,
            user_email=request.user.email if request.user.is_authenticated else "Anonymous"
        )

        return Response({'detail': 'Your application has been submitted successfully!', 'data': serializer.data}, status=status.HTTP_201_CREATED)
    
    
    def generate_admission_number(self):
        """
        Generate a unique admission number in the format RCS000001, RCS000002, etc.
        """
        last_admission = Admission.objects.aggregate(Max('admission_number'))
        last_number = last_admission['admission_number__max']

        if last_number:
            # Extract the numeric part of the last admission number and increment it
            new_number = int(last_number[3:]) + 1
        else:
            # If no admission exists, start with 1
            new_number = 1

        # Format the number with leading zeros, e.g., RCS000001
        return f"RCS{new_number:06d}"

    def update(self, request, pk=None):
        admission = self.get_object()
        original_data = model_to_dict(admission)  # Convert model instance to dict to capture original data

        serializer = self.get_serializer(admission, data=request.data, partial=False)
        serializer.is_valid(raise_exception=True)
        updated_admission = serializer.save()

        # Log changes
        self.log_changes(original_data, updated_admission, request.user)

        return Response(serializer.data)

    def partial_update(self, request, pk=None):
        admission = self.get_object()
        original_data = model_to_dict(admission)  # Convert model instance to dict to capture original data

        serializer = self.get_serializer(admission, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        updated_admission = serializer.save()

        # Log changes
        self.log_changes(original_data, updated_admission, request.user)

        return Response(serializer.data)

    # Define log_changes to compare the original and updated data
    def log_changes(self, original_data, updated_admission, user):
        """
        Log the changes made to the admission inquiry.
        """
        updated_data = model_to_dict(updated_admission)  # Convert updated model instance to dict
        changed_fields = self.get_changed_fields(original_data, updated_data)
        if changed_fields:
            AdmissionLog.objects.create(
                admission=updated_admission,
                user=user,
                user_email=user.email if user else "Anonymous",
                changed_fields=changed_fields
            )

    # Define get_changed_fields to detect differences between original and updated data
    def get_changed_fields(self, original_data, updated_data):
        """
        Compare original and updated data and return a list of fields that changed.
        """
        changed_fields = []
        for key, original_value in original_data.items():
            updated_value = updated_data.get(key)
            if original_value != updated_value:
                changed_fields.append(f"{key}: {original_value} -> {updated_value}")
        return ', '.join(changed_fields)  # Return a string representation of the changes

    def get_permissions(self):
        if self.action in ['update', 'partial_update']:
            self.permission_classes = [IsAuthenticated]
        else:
            self.permission_classes = [AllowAny]
        return super().get_permissions()


class AdmissionLogViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AdmissionLogSerializer

    def get_queryset(self):
        admission_id = self.kwargs['admission_id']
        return AdmissionLog.objects.filter(admission__id=admission_id)

    @action(detail=True, methods=['get'])
    def logs(self, request, pk=None):
        logs = self.get_queryset()
        serializer = self.get_serializer(logs, many=True)
        return Response(serializer.data)
