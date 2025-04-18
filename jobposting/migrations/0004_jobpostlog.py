# Generated by Django 5.1.6 on 2025-03-25 21:34

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jobposting', '0003_jobpost_applications_count'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='JobPostLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_email', models.EmailField(blank=True, max_length=255)),
                ('changed_fields', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('action_type', models.CharField(choices=[('CREATE', 'Create'), ('UPDATE', 'Update'), ('STATUS_CHANGE', 'Status Change'), ('PUBLISH', 'Publish'), ('SCHEDULE', 'Schedule')], max_length=50)),
                ('job_post', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='logs', to='jobposting.jobpost')),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
