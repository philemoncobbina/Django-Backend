# Generated by Django 5.0.6 on 2024-08-20 21:53

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tickets', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticket',
            name='ticket_id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
    ]