from .models import Survivor, Assault
from .models import User
from django import forms


class SurvivorSignUpForm(forms.ModelForm):
    client_code = forms.CharField(required=False)
    mobile_number = forms.IntegerField()
    email = forms.EmailField()
    password = forms.CharField()
    consent = forms.BooleanField(required=False)

    class Meta:
        model = Survivor
        exclude = ('user', 'consent')


class AssaultForm(forms.ModelForm):
    class Meta:
        model = Assault
        fields = (
            'type_of_violence', 'first_name', 'last_name', 'gender', 'build', 'height', 'eye_color',
            'special_body_mark',
            'mobile_number', 'hair_color', 'skin_color', 'race')


class AssaultQuestionAnswerForm(forms.ModelForm):
    class Meta:
        model = Assault
        fields = (
            'year', 'time', 'date', 'anything_else_about_date', 'where_it_happened', 'tell_anyone',
            'after_before_incident',
            'information_about_people_told', 'info_about_people_described_above', 'offender_told_anyone',
            'consent_details',
            'what_happened', 'number_of_offenders', 'anyone_else_with_offender', 'name_of_person_with_offender',
            'info_about_person_with_offender', 'other_info_about_person_with_offender', 'evidence')


class SurvivorLoginByEmailForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('email', 'password')
