# Generated by Django 5.0.2 on 2024-04-23 16:41

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('SecFileSharingApp', '0009_alter_group_encrypted_symmetric_key_and_more'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='groupmember',
            unique_together={('group', 'user')},
        ),
    ]
