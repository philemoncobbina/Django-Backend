# Generated by Django 5.0.6 on 2024-10-19 21:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authapp', '0015_alter_customuser_role'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='is_blocked',
            field=models.BooleanField(default=False),
        ),
    ]