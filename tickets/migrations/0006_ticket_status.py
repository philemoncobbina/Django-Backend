# Generated by Django 5.0.6 on 2024-10-12 16:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tickets', '0005_alter_ticket_ticket_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticket',
            name='status',
            field=models.CharField(choices=[('unattended', 'Unattended'), ('in_progress', 'In Progress'), ('resolved', 'Resolved')], default='unattended', max_length=20),
        ),
    ]