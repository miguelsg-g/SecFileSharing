# Generated by Django 5.0.2 on 2024-08-26 23:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SecFileSharingApp', '0014_appuser_totp_key_otp'),
    ]

    operations = [
        migrations.AddField(
            model_name='appuser',
            name='failed_attempts',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='appuser',
            name='lock_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]