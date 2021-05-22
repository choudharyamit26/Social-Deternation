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
    last_name = models.CharField(default='', max_length=100, null=True, blank=True)
    email = models.CharField(default='', max_length=255, unique=True)
    country_code = models.CharField(default='+91', max_length=10)
    phone_number = models.CharField(default='', max_length=18)
    password = models.CharField(default='', max_length=100)
    confirm_password = models.CharField(default='', max_length=100)
    is_subadmin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()
    USERNAME_FIELD = 'email'

    class Meta:
        ordering = ('-created_at',)
