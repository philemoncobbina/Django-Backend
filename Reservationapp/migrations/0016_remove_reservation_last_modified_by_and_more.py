# Generated by Django 5.0.6 on 2024-09-23 14:54

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Reservationapp', '0015_alter_reservation_full_name'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveField(
            model_name='reservation',
            name='last_modified_by',
        ),
        migrations.AlterField(
            model_name='reservation',
            name='full_name',
            field=models.CharField(max_length=100),
        ),
        migrations.CreateModel(
            name='ReservationLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('changed_fields', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('reservation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Reservationapp.reservation')),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]