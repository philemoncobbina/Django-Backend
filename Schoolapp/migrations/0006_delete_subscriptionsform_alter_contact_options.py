# Generated by Django 5.0.6 on 2024-10-02 21:31

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Schoolapp', '0005_contactlog'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Subscriptionsform',
        ),
        migrations.AlterModelOptions(
            name='contact',
            options={'ordering': ['-timestamp'], 'verbose_name': 'Contact', 'verbose_name_plural': 'Contacts'},
        ),
    ]