# Generated by Django 4.0.5 on 2022-07-22 13:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('workers', '0004_alter_token_operator'),
    ]

    operations = [
        migrations.RenameField(
            model_name='mobileoperator',
            old_name='country_cody',
            new_name='country_code',
        ),
    ]
