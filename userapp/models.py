from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    fingerprint = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        return self.username