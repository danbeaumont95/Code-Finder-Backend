# Generated by Django 4.1.5 on 2023-02-05 20:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("code_finder_api", "0004_codesnippet"),
    ]

    operations = [
        migrations.AddField(
            model_name="codesnippet",
            name="title",
            field=models.CharField(default=None, max_length=80),
        ),
    ]