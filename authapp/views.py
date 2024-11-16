from rest_framework import generics, permissions, status
import requests
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate, login, logout
from .serializers import PasswordResetSerializer, PasswordResetConfirmSerializer, ChangePasswordRequestSerializer , CustomUserSerializer , ChangePasswordSerializer
from django.contrib.auth import get_user_model
from rest_framework_jwt.settings import api_settings 
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
import platform
import logging
from django.shortcuts import get_object_or_404, redirect
import os
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth.hashers import check_password
from django.utils.crypto import get_random_string
from django.contrib.auth.hashers import make_password
from rest_framework.permissions import IsAuthenticated, AllowAny
import base64
from sib_api_v3_sdk import Configuration, ApiClient, SendSmtpEmail
from sib_api_v3_sdk.api.transactional_emails_api import TransactionalEmailsApi
from sib_api_v3_sdk.rest import ApiException
from django.template.loader import render_to_string
from geoip2 import database 
import threading
import platform
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from authapp.models import CustomUser
from authapp.serializers import CustomUserSerializer
from django.core.exceptions import ObjectDoesNotExist



from .serializers import CustomUserSerializer

User = get_user_model()
logger = logging.getLogger(__name__)

class UserDetailView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = CustomUserSerializer

    def get_object(self):
        return self.request.user


class SignUpView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomUserSerializer

    def create(self, request, *args, **kwargs):
        # Make request data mutable
        mutable_data = request.data.copy()

        email = mutable_data.get('email')

        # Check if the email already exists
        if CustomUser.objects.filter(email=email).exists():
            print(f"[INFO] Email {email} already exists in the database.")
            return Response({'error': 'Email has already been used.'}, status=status.HTTP_400_BAD_REQUEST)

        # Modify the mutable data to set the user as inactive initially
        mutable_data['is_active'] = False
        request._mutable_data = mutable_data
        print(f"[INFO] User data modified, setting is_active=False for email: {email}")

        # Perform the user creation
        print(f"[INFO] Attempting to create user with email: {email}")
        serializer = self.get_serializer(data=mutable_data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        # Try to get the user instance that was just created
        try:
            user = CustomUser.objects.get(email=email)
            print(f"[INFO] User {email} successfully created with ID {user.id}.")
        except ObjectDoesNotExist:
            print(f"[ERROR] Failed to find user {email} after creation attempt.")
            return Response({'error': 'User creation failed.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Asynchronously send verification email
        print(f"[INFO] Starting verification email thread for user {email}.")
        threading.Thread(target=self.send_verification_email, args=(user, request)).start()

        # Return a success response
        response = Response(serializer.data, status=status.HTTP_201_CREATED)
        response.data['message'] = 'User registration successful. Please check your email for the verification link.'
        print(f"[INFO] Registration successful for user {email}. Returning response to client.")
        return response

    def send_verification_email(self, user, request):
        print(f"[INFO] Preparing to send verification email to {user.email}...")
        try:
            # Generate the verification token and URL
            verification_token = RefreshToken.for_user(user).access_token
            verification_url = reverse('verify-email', kwargs={'user_id': user.id, 'token': str(verification_token)})
            verification_url = request.build_absolute_uri(verification_url)  # Make the URL absolute
            print(f"[INFO] Verification URL generated for {user.email}: {verification_url}")

            # Render the HTML content from the template
            context = {'verification_url': verification_url}
            html_content = render_to_string('email_verification.html', context)
            print(f"[INFO] HTML content rendered for email verification for {user.email}.")

            # Brevo email sending logic
            configuration = Configuration()
            configuration.api_key['api-key'] = settings.BREVO_API_KEY
            api_instance = TransactionalEmailsApi(ApiClient(configuration))

            send_smtp_email = SendSmtpEmail(
                to=[{"email": user.email}],
                sender={"name": "Your Company", "email": settings.DEFAULT_FROM_EMAIL},
                subject="Verify Your Email",
                html_content=html_content  # Use the rendered HTML content here
            )

            # Send the email
            print(f"[INFO] Attempting to send email to {user.email}...")
            api_instance.send_transac_email(send_smtp_email)
            print(f"[INFO] Verification email successfully sent to {user.email}")

        except ApiException as e:
            print(f"[ERROR] Exception when sending email to {user.email}: {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected error when preparing or sending email to {user.email}: {e}")            

class VerifyEmailView(APIView):
    def get(self, request, user_id, token):
        user = get_object_or_404(User, id=user_id)

        if user.is_active:
            return redirect('http://localhost:5173/dashboard')  # Redirect to the dashboard if already verified

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id_from_token = payload['user_id']

            logger.debug(f"user_id: {user_id}, user_id_from_token: {user_id_from_token}")

            if str(user_id) != str(user_id_from_token):  # Ensure the types match and compare values
                return Response({'error': 'Invalid token for this user.'}, status=status.HTTP_400_BAD_REQUEST)

            # Perform additional checks if needed (e.g., email matching)

            user.is_active = True
            user.save()

            return redirect('http://localhost:5173/dashboard')  # Redirect to the dashboard after successful verification

        except jwt.ExpiredSignatureError:
            logger.error("Activation link has expired.")
            return Response({'error': 'Activation link has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        except jwt.InvalidTokenError:
            logger.error("Invalid activation link.")
            return Response({'error': 'Invalid activation link.'}, status=status.HTTP_400_BAD_REQUEST)


def get_ip_address():
    try:
        ip_response = requests.get('https://api.ipify.org?format=json')
        ip_data = ip_response.json()
        print(f"Public IP address fetched: {ip_data['ip']}")
        return ip_data['ip']
    except Exception as e:
        print(f"Could not fetch IP address: {e}")
        return None

def get_location_info(ip_address):
    try:
        geo_response = requests.get(f'https://ipapi.co/{ip_address}/json/')
        geo_data = geo_response.json()
        if geo_response.status_code == 200:
            return geo_data
        else:
            print(f"Could not fetch geolocation data for IP: {ip_address}")
            return None
    except Exception as e:
        print(f"Error occurred while fetching location information: {e}")
        return None

def get_country_details(country_code):
    try:
        countries_response = requests.get('https://restcountries.com/v3.1/all')
        countries_data = countries_response.json()
        country_dict = {country.get('cca2'): country for country in countries_data}
        if country_code in country_dict:
            return {
                "name": country_dict[country_code].get('name', {}).get('common'),
                "capital": country_dict[country_code].get('capital', [None])[0],
                "region": country_dict[country_code].get('region'),
                "subregion": country_dict[country_code].get('subregion'),
                "population": country_dict[country_code].get('population'),
                "area": country_dict[country_code].get('area'),
            }
        else:
            return None
    except Exception as e:
        print(f"Could not fetch country details: {e}")
        return None

def send_login_email(user, request, ip_address, city, country_name, device_os, device_name):
    try:
        # Prepare email content for login alert using the template
        verification_token = RefreshToken.for_user(user).access_token
        verification_url = reverse('verify-email', kwargs={'user_id': user.id, 'token': str(verification_token)})
        verification_url = request.build_absolute_uri(verification_url)

        # Render the HTML content from the template
        context = {
            'verification_url': verification_url,
            'first_name': user.first_name,
            'city': city,
            'country_name': country_name,
            'ip_address': ip_address,
            'device_os': device_os,
            'device_name': device_name,
        }
        html_content = render_to_string('login_alert.html', context)

        # Brevo email sending logic
        configuration = Configuration()
        configuration.api_key['api-key'] = settings.BREVO_API_KEY
        api_instance = TransactionalEmailsApi(ApiClient(configuration))

        send_smtp_email = SendSmtpEmail(
            to=[{"email": user.email, "name": user.first_name}],
            sender={"name": "Your Company", "email": settings.DEFAULT_FROM_EMAIL},
            subject="New Login Alert",
            html_content=html_content
        )

        # Send email
        api_instance.send_transac_email(send_smtp_email)
        print(f"Email sent successfully to: {user.email}")

    except ApiException as e:
        print(f"Error sending email to {user.email}: {e}")

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        print(f"Login attempt for email: {email}")

        try:
            user = CustomUser.objects.get(email=email)
            print(f"User found: {user.email}")
        except CustomUser.DoesNotExist:
            print(f"User not found with email: {email}")
            return Response({'error': 'Incorrect username or password.'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Check if the user has a defined role
        if user.role:
            print(f"Access denied for user with role: {user.role}")
            return Response({'error': 'You are not authorized to access this system.'}, status=status.HTTP_403_FORBIDDEN)

        # Check if the user is blocked
        if user.is_blocked:
            print(f"User is blocked: {user.email}")
            return Response({'error': 'Your account has been blocked. Please contact support for assistance.'}, status=status.HTTP_403_FORBIDDEN)

        # Check if the user is active
        if not user.is_active:
            print(f"User is not active: {user.email}")
            return Response({'error': 'Account not verified. Please check your email for the verification link.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if the password matches
        if check_password(password, user.password):
            print(f"Password check passed for user: {user.email}")
            login(request, user)
            refresh = RefreshToken.for_user(user)

            # Get the IP address and other details asynchronously
            ip_address = get_ip_address() or 'N/A'
            city = 'N/A'
            country_code = 'N/A'
            device_os = platform.system()  # OS name
            device_name = platform.node()  # Hostname / Network name

            # Asynchronously run the tasks
            def async_task():
                location_info = get_location_info(ip_address)
                if location_info:
                    city = location_info.get('city', 'N/A')
                    country_code = location_info.get('country', 'N/A')

                country_details = get_country_details(country_code)
                country_name = country_details['name'] if country_details else 'N/A'

                # Call the function to send the login email
                send_login_email(user, request, ip_address, city, country_name, device_os, device_name)

            # Run async task in a separate thread
            threading.Thread(target=async_task).start()

            return Response({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'role': user.role
                }
            })
        else:
            print(f"Password check failed for user: {email}")
            return Response({'error': 'Incorrect username or password.'}, status=status.HTTP_401_UNAUTHORIZED)
        


            
class PasswordResetView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetSerializer

    def get(self, request, *args, **kwargs):
        email = request.query_params.get('email')
        if email:
            user = User.objects.filter(email=email).first()
            if user and user.is_active:
                return Response({'message': 'Email is registered.'}, status=status.HTTP_200_OK)
            return Response({'error': 'Email not registered or not active.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'error': 'Email parameter is missing.'}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email=email).first()
            if user and user.is_active:
                verification_code = get_random_string(length=6, allowed_chars='0123456789')
                user.verification_code = verification_code
                user.save()

                # Send verification email
                context = {
                    'verification_code': verification_code,
                }
                subject = 'Password Reset Verification Code'
                to_email = email
                self.send_verification_email(subject, context, to_email)

                logger.info(f"Password reset verification code sent to {email}.")
                return Response({'message': 'Verification code sent to your email.'}, status=status.HTTP_200_OK)
            return Response({'error': 'Email not registered or not active.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_verification_email(self, subject, context, to_email):
        # Render the HTML content from the template
        html_content = render_to_string('password_reset_verification.html', context)

        # Brevo email sending logic
        configuration = Configuration()
        configuration.api_key['api-key'] = settings.BREVO_API_KEY
        
        api_instance = TransactionalEmailsApi(ApiClient(configuration))
        
        send_smtp_email = SendSmtpEmail(
            to=[{"email": to_email}],
            sender={"name": "Your Company", "email": settings.DEFAULT_FROM_EMAIL},
            subject=subject,
            html_content=html_content  # Use the rendered HTML content here
        )

        try:
            api_response = api_instance.send_transac_email(send_smtp_email)
            logger.info(f"Verification email sent to {to_email}: {api_response}")
        except ApiException as e:
            logger.error(f"Exception when sending email: {e}")



class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            verification_code = serializer.validated_data['verification_code']
            new_password = serializer.validated_data['new_password']
            user = User.objects.filter(email=email, verification_code=verification_code).first()
            if user:
                user.password = make_password(new_password)
                user.verification_code = None  # Clear the verification code after successful reset
                user.save()
                logger.info(f"Password successfully reset for {email}.")
                return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyResetCodeView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        verification_code = request.data.get('verification_code')
        user = User.objects.filter(email=email, verification_code=verification_code).first()
        if user:
            return Response({'message': 'Verification code is valid.'}, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)
    


class ChangePasswordRequestView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangePasswordRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            
            if user.email and user.is_active:
                verification_code = get_random_string(length=6, allowed_chars='0123456789')
                user.verification_code = verification_code
                user.save()

                # Send verification email
                context = {'verification_code': verification_code}
                subject = 'Change Password Verification Code'
                to_email = user.email
                self.send_verification_email(subject, context, to_email)

                logger.info(f"Change password verification code sent to {user.email}.")
                return Response({'message': 'Verification code sent to your email.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'User account is not active or email is missing.'}, status=status.HTTP_400_BAD_REQUEST)
                
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_verification_email(self, subject, context, to_email):
        # Render the HTML content from the template
        html_content = render_to_string('change_password_verification.html', context)

        # Brevo email sending logic
        configuration = Configuration()
        configuration.api_key['api-key'] = settings.BREVO_API_KEY
        
        api_instance = TransactionalEmailsApi(ApiClient(configuration))
        
        send_smtp_email = SendSmtpEmail(
            to=[{"email": to_email}],
            sender={"name": "Your Company", "email": settings.DEFAULT_FROM_EMAIL},
            subject=subject,
            html_content=html_content  # Use the rendered HTML content here
        )

        try:
            api_response = api_instance.send_transac_email(send_smtp_email)
            logger.info(f"Verification email sent to {to_email}: {api_response}")
        except ApiException as e:
            logger.error(f"Exception when sending email: {e}")

class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            verification_code = serializer.validated_data['verification_code']
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            
            if user.verification_code != verification_code:
                return Response({'error': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)
            
            if not user.check_password(old_password):
                return Response({'error': 'Invalid old password.'}, status=status.HTTP_400_BAD_REQUEST)
            
            user.set_password(new_password)
            user.verification_code = None  # Clear the verification code after successful reset
            user.save()
            
            logger.info(f"Password successfully changed for {user.email}.")
            return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class VerifyChangePasswordCodeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        verification_code = request.data.get('verification_code')
        if user.verification_code == verification_code:
            return Response({'message': 'Verification code is valid.'}, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)
    
    

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response({'detail': 'Logout successful'})