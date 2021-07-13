from django.contrib import admin
from .models import User, Organization, SubscriptionPlan, SubscriptionStatus, QuestionCategory, Otp, \
    AssaultFormQuestions

# Register your models here.
admin.site.register(User)
admin.site.register(Organization)
admin.site.register(SubscriptionPlan)
admin.site.register(SubscriptionStatus)
admin.site.register(Otp)
admin.site.register(AssaultFormQuestions)
admin.site.register(QuestionCategory)
