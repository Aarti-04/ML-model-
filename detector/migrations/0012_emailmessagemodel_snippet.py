# Generated by Django 5.0.4 on 2024-05-10 06:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("detector", "0011_rename_to_emailmessagemodel_to_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="emailmessagemodel",
            name="snippet",
            field=models.TextField(default=""),
        ),
    ]
