# Generated by Django 4.2.11 on 2024-05-17 10:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("detector", "0003_alter_emailmessagemodel_snippet"),
    ]

    operations = [
        migrations.AlterField(
            model_name="emailmessagemodel",
            name="header",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
