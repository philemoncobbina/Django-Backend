from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone

class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        if not username:
            raise ValueError('The Username field must be set')
        
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', 'principal')

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, username, password, **extra_fields)
    
    def create_student(self, email, first_name, last_name, password, index_number, class_name, **extra_fields):
        # Generate username from index number if not provided
        username = index_number.lower()  # or any other logic you prefer
        
        extra_fields.setdefault('role', 'student')
        extra_fields.setdefault('is_active', True)
        extra_fields['index_number'] = index_number
        extra_fields['class_name'] = class_name
        
        user = self.create_user(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=password,
            **extra_fields
        )
        return user

class CustomUser(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ('principal', 'Principal'),
        ('staff', 'Staff'),
        ('student', 'Student'),  # Added student role
    )
    
    CLASS_CHOICES = (
        ('creche', 'Creche'),
        ('nursery', 'Nursery'),
        ('kg1', 'KG 1'),
        ('kg2', 'KG 2'),
        ('1', 'Class 1'),
        ('2', 'Class 2'),
        ('3', 'Class 3'),
        ('4', 'Class 4'),
        ('5', 'Class 5'),
        ('6', 'Class 6'),
        ('jhs1', 'JHS 1'),
        ('jhs2', 'JHS 2'),
        ('jhs3', 'JHS 3'),
    )
    
    username = models.CharField(max_length=150, unique=False, default="default_username")
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    password = models.CharField(max_length=128)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_blocked = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    verification_code = models.CharField(max_length=6, null=True, blank=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    is_google_account = models.BooleanField(default=False)
    
    # Student-specific fields
    index_number = models.CharField(max_length=20, unique=True, null=True, blank=True)
    class_name = models.CharField(max_length=10, choices=CLASS_CHOICES, null=True, blank=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email
    
    @property
    def is_student(self):
        return self.role == 'student'