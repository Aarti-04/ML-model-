# Generated by Django 4.2.11 on 2024-05-16 05:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("detector", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="emailmessagemodel",
            name="is_deleted",
            field=models.BooleanField(blank=True, default=False),
        ),
    ]
