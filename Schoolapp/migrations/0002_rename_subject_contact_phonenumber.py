# Generated by Django 4.2.9 on 2024-06-08 23:35

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Schoolapp', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='contact',
            old_name='subject',
            new_name='phoneNumber',
        ),
    ]