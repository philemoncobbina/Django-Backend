# Generated by Django 5.0.6 on 2024-09-06 23:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authapp', '0011_remove_customuser_role'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='username',
            field=models.CharField(default='default_username', max_length=150),
        ),
    ]