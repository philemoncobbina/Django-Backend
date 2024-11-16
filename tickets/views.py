from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from .models import Ticket, TicketLog
from .serializers import TicketSerializer, TicketLogSerializer
from django.utils import timezone
from sib_api_v3_sdk import Configuration, ApiClient, SendSmtpEmail
from sib_api_v3_sdk.api.transactional_emails_api import TransactionalEmailsApi
from django.conf import settings
from rest_framework import generics
from sib_api_v3_sdk.rest import ApiException
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.db.models import Max

class TicketViewSet(viewsets.ModelViewSet):
    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Generate a unique TicketID
        ticket_id = self.generate_ticket_id()
        serializer.validated_data['TicketID'] = ticket_id

        # Save the ticket
        ticket = serializer.save()

        # Send confirmation email
        self.send_ticket_confirmation_email(ticket)

        return Response({'detail': 'Ticket submitted successfully!', 'data': serializer.data}, status=status.HTTP_201_CREATED)

    def generate_ticket_id(self):
        last_ticket = Ticket.objects.filter(TicketID__regex=r'^RCSTK\d{4}$').aggregate(Max('TicketID'))
        last_ticket_id = last_ticket['TicketID__max']

        if last_ticket_id:
            new_id_number = int(last_ticket_id[5:]) + 1
        else:
            new_id_number = 1

        return f"RCSTK{new_id_number:04d}"

    def send_ticket_confirmation_email(self, ticket):
        configuration = Configuration()
        configuration.api_key['api-key'] = settings.BREVO_API_KEY

        api_instance = TransactionalEmailsApi(ApiClient(configuration))

        send_smtp_email = SendSmtpEmail(
            to=[{"email": ticket.email}],
            sender={"name": "Support Team", "email": settings.DEFAULT_FROM_EMAIL},
            subject="Your Support Ticket ID",
            html_content=f"""
            <html>
            <body>
                <p>Dear {ticket.full_name},</p>
                <p>Your ticket ID is <strong>{ticket.TicketID}</strong>.</p>
                <p>We will review your request soon.</p>
                <p>Best regards,<br>Support Team</p>
            </body>
            </html>
            """
        )

        try:
            api_response = api_instance.send_transac_email(send_smtp_email)
            print("Confirmation email sent successfully:", api_response)
        except ApiException as e:
            print(f"Exception when sending email: {e}")

    def get_permissions(self):
        if self.action in ['update', 'partial_update']:
            self.permission_classes = [IsAuthenticated]
        else:
            self.permission_classes = [AllowAny]
        return super().get_permissions()

    def update(self, request, pk=None):
        ticket = self.get_object()
        
        # Get original data before update
        original_data = TicketSerializer(ticket).data

        # Create a new request data dict without the screenshot
        request_data = request.data.copy()
        if 'screenshot' in request_data:
            del request_data['screenshot']  # Remove screenshot from update request

        serializer = self.get_serializer(ticket, data=request_data, partial=False)
        serializer.is_valid(raise_exception=True)

        # Save updated ticket
        serializer.save()

        # Track changes
        updated_data = serializer.data
        changed_fields = self.get_changed_fields(original_data, updated_data)

        TicketLog.objects.create(
            ticket=ticket,
            user=request.user,
            user_email=request.user.email,
            changed_fields=changed_fields
        )

        return Response(serializer.data)

    def get_changed_fields(self, original_data, updated_data):
        changed_fields = []
        for key, original_value in original_data.items():
            updated_value = updated_data.get(key)
            if original_value != updated_value:
                changed_fields.append(f"{key}: {original_value} -> {updated_value}")
        return ', '.join(changed_fields)


class TicketLogListView(generics.ListAPIView):
    serializer_class = TicketLogSerializer

    def get_queryset(self):
        ticket_id = self.kwargs['ticket_id']
        return TicketLog.objects.filter(ticket_id=ticket_id)
