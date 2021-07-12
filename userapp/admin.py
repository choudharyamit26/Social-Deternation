from django.contrib import admin
from .models import Assault, ServiceProvider, ServiceProviderSlots,Survivor,ServiceProviderCategory

# Register your models here.
admin.site.register(Assault)
admin.site.register(ServiceProvider)
admin.site.register(ServiceProviderSlots)
admin.site.register(Survivor)
admin.site.register(ServiceProviderCategory)
