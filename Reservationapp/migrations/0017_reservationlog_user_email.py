# Generated by Django 5.0.6 on 2024-09-23 16:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Reservationapp', '0016_remove_reservation_last_modified_by_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='reservationlog',
            name='user_email',
            field=models.EmailField(blank=True, max_length=255),
        ),
    ]