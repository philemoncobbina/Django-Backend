# Generated by Django 5.0.6 on 2024-09-23 16:20

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Reservationapp', '0017_reservationlog_user_email'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='reservationlog',
            name='user_email',
        ),
    ]