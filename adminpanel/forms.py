from django import forms
from .models import User


class AdminLoginForm(forms.Form):
    class Meta:
        model = User
