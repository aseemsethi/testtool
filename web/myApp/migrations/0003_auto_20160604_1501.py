# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-06-04 15:01
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('myApp', '0002_auto_20160604_1400'),
    ]

    operations = [
        migrations.RenameField(
            model_name='cfg',
            old_name='port',
            new_name='sslPort',
        ),
    ]
