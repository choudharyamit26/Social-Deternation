from django.db import models
from adminpanel.models import User


class Survivor(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    client_code = models.CharField(default='', max_length=100)
    mobile_number = models.BigIntegerField()
    email = models.EmailField()
    password = models.CharField(default='', max_length=200)
    consent = models.BooleanField(default=False)


class Assault(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    type_of_violence = models.CharField(default='', max_length=100)
    first_name = models.CharField(default='', max_length=100)
    last_name = models.CharField(default='', max_length=100)
    gender = models.CharField(default='', max_length=100)
    build = models.CharField(default='', max_length=100)
    height = models.CharField(default='', max_length=100)
    eye_color = models.CharField(default='', max_length=100)
    special_body_mark = models.CharField(default='', max_length=300)
    mobile_number = models.CharField(default='', max_length=300)
    hair_color = models.CharField(default='', max_length=100)
    skin_color = models.CharField(default='', max_length=100)
    race = models.CharField(default='', max_length=100)
    year = models.BigIntegerField()
    time = models.TimeField()
    date = models.DateField()
    anything_else_about_date = models.CharField(default='', max_length=2000)
    where_it_happened = models.CharField(default='', max_length=2000)
    other_info_about_location = models.CharField(default='', max_length=2000)
    anyone_see_hear = models.CharField(default='', max_length=1000)
    tell_anyone = models.CharField(default='', max_length=1000)
    after_before_incident = models.CharField(default='', max_length=1000)
    information_about_people_told = models.CharField(default='', max_length=3000)
    info_about_people_described_above = models.CharField(default='', max_length=3000)
    offender_told_anyone = models.CharField(default='', max_length=1000)
    consent_details = models.CharField(default='', max_length=4000)
    what_happened = models.CharField(default='', max_length=3000)
    number_of_offenders = models.IntegerField()
    anyone_else_with_offender = models.CharField(default='', max_length=4000)
    name_of_person_with_offender = models.CharField(default='', max_length=4000)
    info_about_person_with_offender = models.CharField(default='', max_length=4000)
    other_info_about_person_with_offender = models.CharField(default='', max_length=4000)
    evidence = models.CharField(default='', max_length=4000)
    allow_info_match = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class AssaultQuestionAnswer(models.Model):
    pass


class Faq(models.Model):
    pass


class Contact(models.Model):
    pass


class Notification:
    pass


class ServiceProvider(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    organization = models.CharField(default='', max_length=1000)
    organization_type = models.CharField(default='', max_length=1000)
    mobile_number = models.BigIntegerField()
    email = models.EmailField()
    password = models.CharField(default='', max_length=2000)
    company_logo = models.ImageField(upload_to='media')
    company_name = models.CharField(default='', max_length=1000)
    contact_persons_first_name = models.CharField(default='', max_length=1000)
    contact_persons_last_name = models.CharField(default='', max_length=1000)
    company_address_1 = models.CharField(default='', max_length=1000)
    company_address_2 = models.CharField(default='', max_length=1000)
    country = models.CharField(default='', max_length=1000)
    city = models.CharField(default='', max_length=100)
    zip_code = models.CharField(default='', max_length=100)


class ServiceProviderSlots(models.Model):
    user = models.ForeignKey(ServiceProvider, on_delete=models.CASCADE)
    slot_date = models.DateField()
    slot_time = models.CharField(default='', max_length=300)
    select_slot_type = models.CharField(default='', max_length=300)
