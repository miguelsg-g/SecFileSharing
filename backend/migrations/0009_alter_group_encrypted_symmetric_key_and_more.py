# Generated by Django 5.0.2 on 2024-04-22 18:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SecFileSharingApp', '0008_alter_group_encrypted_symmetric_key_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='group',
            name='encrypted_symmetric_key',
            field=models.BinaryField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='groupmember',
            name='encrypted_symmetric_key',
            field=models.BinaryField(blank=True, null=True),
        ),
    ]
