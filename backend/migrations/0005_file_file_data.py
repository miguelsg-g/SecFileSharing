# Generated by Django 5.0.2 on 2024-04-21 12:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SecFileSharingApp', '0004_rename_private_key_group_encrypted_symmetric_key_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='file_data',
            field=models.BinaryField(default=None),
            preserve_default=False,
        ),
    ]
