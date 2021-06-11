from django.contrib import admin
from .models import Assault, ServiceProvider, ServiceProviderSlots

# Register your models here.
admin.site.register(Assault)
admin.site.register(ServiceProvider)
admin.site.register(ServiceProviderSlots)
