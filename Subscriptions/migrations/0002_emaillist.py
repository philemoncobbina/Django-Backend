# Generated by Django 5.0.6 on 2024-10-26 20:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Subscriptions', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailList',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('emails', models.TextField()),
            ],
        ),
    ]