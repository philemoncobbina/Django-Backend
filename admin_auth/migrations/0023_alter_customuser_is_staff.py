# Generated by Django 5.0.6 on 2024-09-02 17:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('admin_auth', '0022_customuser_groups_customuser_is_superuser_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='is_staff',
            field=models.BooleanField(default=True),
        ),
    ]