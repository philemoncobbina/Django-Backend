# Generated by Django 5.0.6 on 2024-10-06 11:12

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Admissionapp', '0006_alter_student_country_of_citizenship'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Admission',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('submit_date', models.DateTimeField(default=django.utils.timezone.now)),
                ('admission_number', models.CharField(max_length=10, unique=True)),
                ('first_name', models.CharField(max_length=255)),
                ('last_name', models.CharField(max_length=255)),
                ('middle_name', models.CharField(blank=True, max_length=255, null=True)),
                ('home_address', models.CharField(max_length=255)),
                ('age', models.IntegerField()),
                ('language_spoken', models.CharField(max_length=255)),
                ('country_of_citizenship', models.CharField(max_length=255)),
                ('gender', models.CharField(max_length=10)),
                ('date_of_birth', models.DateField()),
                ('parent_full_name', models.CharField(max_length=255)),
                ('occupation', models.CharField(max_length=255)),
                ('phone_number', models.CharField(max_length=15)),
                ('email', models.EmailField(max_length=254)),
                ('parent_home_address', models.CharField(max_length=255)),
                ('previous_school_name', models.CharField(max_length=255)),
                ('previous_class', models.CharField(max_length=10)),
                ('previous_school_address', models.CharField(max_length=255)),
                ('start_date', models.DateField()),
                ('end_date', models.DateField()),
                ('emergency_contact', models.CharField(max_length=255)),
                ('emergency_contact_number', models.CharField(max_length=15)),
                ('medical_conditions', models.CharField(max_length=255)),
                ('allergies', models.CharField(max_length=255)),
                ('disabilities', models.CharField(choices=[('Yes', 'Yes'), ('No', 'No')], max_length=3)),
                ('vaccinated', models.CharField(choices=[('Yes', 'Yes'), ('No', 'No')], max_length=3)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('in_review', 'In Review'), ('approved', 'Approved'), ('rejected', 'Rejected')], default='pending', max_length=20)),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Admission',
                'verbose_name_plural': 'Admissions',
                'ordering': ['-submit_date'],
            },
        ),
        migrations.CreateModel(
            name='AdmissionLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_email', models.EmailField(blank=True, max_length=255)),
                ('changed_fields', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('admission', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Admissionapp.admission')),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.DeleteModel(
            name='Student',
        ),
    ]
