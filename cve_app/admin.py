from django.contrib import admin
from .models import CVEdetails, SingleCve

# Register your models here.


@admin.register(CVEdetails)
class AdminModelManager(admin.ModelAdmin):
    list_display = ['cve_id']


admin.site.register(SingleCve)
