from django.contrib import admin
from .models import User, Organization, SubscriptionPlan, SubscriptionStatus

# Register your models here.
admin.site.register(User)
admin.site.register(Organization)
admin.site.register(SubscriptionPlan)
admin.site.register(SubscriptionStatus)
