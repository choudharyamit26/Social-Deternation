import base64

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.urls import reverse


class UserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):
        """Creates and saves a new user"""
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password):
        """Creates and saves a new super user"""
        user = self.create_user(email, password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)

        return user


class User(AbstractBaseUser, PermissionsMixin):
    """ User model """
    first_name = models.CharField(default='', max_length=100)
    last_name = models.CharField(default='', max_length=100)
    nick_name = models.CharField(default='', max_length=100)
    avi = models.CharField(default='', max_length=100)
    email = models.CharField(default='', max_length=255, unique=True)
    country_code = models.CharField(default='+91', max_length=10)
    phone_number = models.CharField(default='', max_length=18)
    password = models.CharField(default='', max_length=100)
    confirm_password = models.CharField(default='', max_length=100)
    is_subadmin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_survivor = models.BooleanField(default=False)
    is_service_provider = models.BooleanField(default=False)

    objects = UserManager()
    USERNAME_FIELD = 'email'

    class Meta:
        ordering = ('-created_at',)


class Organization(models.Model):
    organization_name = models.CharField(default='', max_length=200)
    first_name = models.CharField(default='', max_length=200)
    last_name = models.CharField(default='', max_length=200)
    email = models.CharField(default='', max_length=200)
    mobile_number = models.CharField(default='', max_length=200)
    client_code = models.CharField(default='', max_length=200)
    active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class SubscriptionPlan(models.Model):
    plan_type = models.CharField(default='', max_length=300)
    category = models.CharField(default='', max_length=300)
    name = models.CharField(default='', max_length=300)
    description = models.TextField()
    price = models.DecimalField(default=0, max_digits=12, decimal_places=2)
    duration = models.IntegerField(default=0)
    number_of_persons = models.IntegerField(default=0)
    platform = models.CharField(default='', max_length=300)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)


class SubscriptionStatus(models.Model):
    organization_name = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    subscription_plan = models.ForeignKey(SubscriptionPlan, on_delete=models.CASCADE, null=True, blank=True)
    active = models.BooleanField(default=False)


class Otp(models.Model):
    number = models.BigIntegerField(null=True, blank=True)
    email = models.CharField(default='', max_length=100, null=True, blank=True)
    otp = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)


class AssaultFormQuestions(models.Model):
    category = models.CharField(default='', max_length=300)
    question = models.CharField(default='', max_length=300)
    field_type = models.CharField(default='', max_length=200)
    answer_option_1 = models.CharField(default='', max_length=300, null=True, blank=True)
    answer_option_2 = models.CharField(default='', max_length=300, null=True, blank=True)
    answer_option_3 = models.CharField(default='', max_length=300, null=True, blank=True)
    answer_option_4 = models.CharField(default='', max_length=300, null=True, blank=True)
    answer_option_5 = models.CharField(default='', max_length=300, null=True, blank=True)
    answer_option_6 = models.CharField(default='', max_length=300, null=True, blank=True)
    answer_option_7 = models.CharField(default='', max_length=300, null=True, blank=True)
    answer_option_8 = models.CharField(default='', max_length=300, null=True, blank=True)


class QuestionCategory(models.Model):
    category_name = models.CharField(default='', max_length=100)


@receiver(post_save, sender=Organization)
def user_coins(sender, instance, created, **kwargs):
    if created:
        organization_id = instance.id
        organization_obj = Organization.objects.get(id=organization_id)
        # obj = str(organization_id) + str(organization_obj.created_at.strftime("%Y-%m"))
        # organization_obj.client_code = base64.b32encode(obj).upper()
        organization_obj.client_code = (organization_obj.organization_name + str(organization_id) + str(
            organization_obj.created_at.strftime("%m%Y"))).upper()
        organization_obj.save()
