from celery import Celery

from boefjes import celery_config

app = Celery()
app.config_from_object(celery_config)
