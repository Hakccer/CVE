from django.db import models
from django.contrib.auth.models import User

# Create your models here.


class CVEdetails(models.Model):
    cve_id = models.CharField(max_length=30)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date_c = models.CharField(max_length=20)
    time_c = models.CharField(max_length=20)


# Creating different Model for all cve's to avoid data duplicates
class SingleCve(models.Model):
    cve = models.CharField(max_length=30, unique=True)
    cve_data = models.TextField()
