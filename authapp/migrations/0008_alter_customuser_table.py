# Generated by Django 5.0.6 on 2024-09-01 01:38

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authapp', '0007_alter_customuser_groups_and_more'),
    ]

    operations = [
        migrations.AlterModelTable(
            name='customuser',
            table='authapp_customuser',
        ),
    ]