from django.conf.global_settings import DEFAULT_FROM_EMAIL
from django.contrib import messages
from django.contrib.auth import login, logout, get_user_model, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordContextMixin
from django.core.mail import send_mail
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import ListView, View, TemplateView, FormView

from .forms import AdminLoginForm
from .models import User

user = get_user_model()


class LoginView(View):
    model = User
    template_name = 'login.html'
    form_class = AdminLoginForm

    def get(self, *args, **kwargs):
        form = AdminLoginForm()
        try:
            if self.request.COOKIES.get('cid1') and self.request.COOKIES.get('cid2') and self.request.COOKIES.get(
                    'cid3'):
                return render(self.request, 'login.html',
                              {'form': form, 'email': self.request.COOKIES.get('cid1'),
                               'password': self.request.COOKIES.get('cid2'),
                               'remember_me': self.request.COOKIES.get('cid3')})
            else:
                return render(self.request, 'login.html', {'form': form})
        except:
            return render(self.request, 'login.html', {'form': form})

    def post(self, request, *args, **kwargs):
        email = self.request.POST['email']
        password = self.request.POST['password']
        remember_me = self.request.POST.get('remember_me' or None)
        try:
            user_object = user.objects.get(email=email.lower())
            if user_object.check_password(password):
                if user_object.is_superuser:
                    login(self.request, user_object)
                    messages.success(self.request, 'Logged in successfully')
                    if remember_me:
                        cookie_age = 60 * 60 * 24
                        self.request.session.set_expiry(1209600)
                        response = HttpResponse()
                        response.set_cookie('cid1', self.request.POST['email'], max_age=cookie_age)
                        response.set_cookie('cid2', self.request.POST['password'], max_age=cookie_age)
                        response.set_cookie('cid3', self.request.POST['remember_me'], max_age=cookie_age)
                        return response
                    else:
                        self.request.session.set_expiry(0)
                    return redirect('adminpanel:dashboard')
                if user_object.is_subadmin:
                    login(self.request, user_object)
                    messages.success(self.request, 'Logged in successfully')
                    if remember_me:
                        cookie_age = 60 * 60 * 24
                        self.request.session.set_expiry(1209600)
                        response = HttpResponse()
                        response.set_cookie('cid1', self.request.POST['email'], max_age=cookie_age)
                        response.set_cookie('cid2', self.request.POST['password'], max_age=cookie_age)
                        response.set_cookie('cid3', self.request.POST['remember_me'], max_age=cookie_age)
                        return response
                    else:
                        self.request.session.set_expiry(0)
                    return redirect('adminpanel:dashboard')
                else:
                    messages.error(self.request, "You are not authorised")
                    return HttpResponseRedirect(self.request.path_info, status=403)
            else:
                messages.error(self.request, "Incorrect Password")
                return HttpResponseRedirect(self.request.path_info, status=403)
        except Exception as e:
            messages.error(self.request, "Email doesn't exists")
            return HttpResponseRedirect(self.request.path_info, status=403)


class Dashboard(LoginRequiredMixin, View):
    model = User
    template_name = 'index.html'
    login_url = "adminpanel:login"

    def get(self, request, *args, **kwargs):
        return render(self.request, "index.html")


class SubscriptionView(LoginRequiredMixin, ListView):
    model = User
    template_name = "subscription.html"
    login_url = "adminpanel:login"


class SurvivorsView(LoginRequiredMixin, ListView):
    model = User
    template_name = "survivor.html"
    login_url = "adminpanel:login"


class CardInformationView(LoginRequiredMixin, ListView):
    model = User
    template_name = "card-information.html"
    login_url = "adminpanel:login"


class MyProfileView(LoginRequiredMixin, View):
    model = User
    template_name = "profile.html"
    login_url = "adminpanel:login"

    def get(self, request, *args, **kwargs):
        user = self.request.user
        return render(self.request, "profile.html", {"object": user})

    def post(self, request, *args, **kwargs):
        first_name = self.request.POST['first_name']
        last_name = self.request.POST['last_name']
        password = self.request.POST['password']
        phone_number = self.request.POST['phone_number']
        email = self.request.POST['email']
        if email == self.request.user.email:
            user = User.objects.get(email=email)
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            user.phone_number = phone_number
            user.set_password(password)
            user.save()
            update_session_auth_hash(self.request, user)
            messages.success(self.request, "Profile updated successfully")
            return redirect("adminpanel:dashboard")
        else:
            try:
                user = User.objects.get(email=email)
                messages.error(self.request, "User with this email already exists")
                return render(self.request, "profile.html")
            except Exception as e:
                user = self.request.user
                user.first_name = first_name
                user.last_name = last_name
                user.email = email
                user.phone_number = phone_number
                user.set_password(password)
                user.save()
                update_session_auth_hash(self.request, user)
                messages.success(self.request, "Profile updated successfully")
                return redirect("adminpanel:dashboard")


class PasswordResetConfirmView(View):
    template_name = 'password_reset_confirm.html'

    # success_url = reverse_lazy('adminpanel:password_reset_complete')

    def get(self, request, *args, **kwargs):
        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if token_generator.check_token(user_object, token):
            return render(self.request, 'password_reset_confirm.html')
        else:
            messages.error(self.request, "Link is Invalid")
            return render(self.request, 'password_reset_confirm.html')

    def post(self, request, *args, **kwargs):

        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if not token_generator.check_token(user_object, token):
            messages.error(self.request, "Link is Invalid")
            return render(request, 'password_reset_confirm.html')

        password1 = self.request.POST.get('new_password1')
        password2 = self.request.POST.get('new_password2')

        if password1 != password2:
            messages.error(self.request, "Passwords do not match")
            return render(self.request, 'password_reset_confirm.html')
        elif len(password1) < 8:
            messages.error(
                self.request, "Password must be atleast 8 characters long")
            return render(request, 'password_reset_confirm.html')
        elif password1.isdigit() or password2.isdigit() or password1.isalpha() or password2.isalpha():
            messages.error(
                self.request, "Passwords must have a mix of numbers and characters")
            return render(request, 'password_reset_confirm.html')
        else:
            token = kwargs['token']
            user_id_b64 = kwargs['uidb64']
            uid = urlsafe_base64_decode(user_id_b64).decode()
            user_object = user.objects.get(id=uid)
            user_object.set_password(password1)
            user_object.save()
            return redirect('adminpanel:password-reset-complete')


class PasswordResetView(View):
    template_name = 'password_reset.html'

    def get(self, request, *args, **kwargs):
        return render(request, 'password_reset.html')

    def post(self, request, *args, **kwargs):
        user = get_user_model()
        email = request.POST.get('email')
        email_template = "password_reset_email.html"
        user_qs = user.objects.filter(email=email)
        if len(user_qs) == 0:
            messages.error(request, 'Email does not exists')
            return render(request, 'password_reset.html')

        elif len(user_qs) == 1:
            user_object = user_qs[0]
            email = user_object.email
            uid = urlsafe_base64_encode(force_bytes(user_object.id))
            token = default_token_generator.make_token(user_object)
            if request.is_secure():
                protocol = "https"
            else:
                protocol = "http"
            domain = request.META['HTTP_HOST']
            user = user_object
            site_name = "Brasi"

            context = {
                "email": email,
                "uid": uid,
                "token": token,
                "protocol": protocol,
                "domain": domain,
                "user": user,
                "site_name": site_name
            }
            subject = "Reset Password Link"
            email_body = render_to_string(email_template, context)
            send_mail(subject, email_body, DEFAULT_FROM_EMAIL,
                      [email], fail_silently=False)
            return redirect('adminpanel:password-reset-done')
        else:

            user_object = user_qs[0]
            email = user_object.email
            uid = urlsafe_base64_encode(force_bytes(user_object.id))
            token = default_token_generator.make_token(user_object)
            if request.is_secure():
                protocol = "https"
            else:
                protocol = "http"
            domain = request.META['HTTP_HOST']
            user = user_object
            site_name = "Brasi"

            context = {
                "email": email,
                "uid": uid,
                "token": token,
                "protocol": protocol,
                "domain": domain,
                "user": user,
                "site_name": site_name
            }

            subject = "Reset Password Link"
            email_body = render_to_string(email_template, context)
            send_mail(subject, email_body, DEFAULT_FROM_EMAIL,
                      [email], fail_silently=False)
            return redirect('adminpanel:password-reset-done')


class SuperAdminLogin(View):
    model = User
    template_name = 'superadmin/login.html'
    form_class = AdminLoginForm

    def get(self, request, *args, **kwargs):
        form = AdminLoginForm()
        try:
            if self.request.COOKIES.get('cid1') and self.request.COOKIES.get('cid2') and self.request.COOKIES.get(
                    'cid3'):
                return render(self.request, 'superadmin/login.html',
                              {'form': form, 'email': self.request.COOKIES.get('cid1'),
                               'password': self.request.COOKIES.get('cid2'),
                               'remember_me': self.request.COOKIES.get('cid3')})
            else:
                return render(self.request, 'superadmin/login.html', {'form': form})
        except:
            return render(self.request, 'superadmin/login.html', {'form': form})
        # return render(self.request, "superadmin/login.html")

    def post(self, request, *args, **kwargs):
        email = self.request.POST['email']
        password = self.request.POST['password']
        remember_me = self.request.POST.get('remember_me' or None)
        try:
            user_object = user.objects.get(email=email.lower())
            if user_object.check_password(password):
                if user_object.is_superuser:
                    login(self.request, user_object)
                    messages.success(self.request, 'Logged in successfully')
                    if remember_me:
                        cookie_age = 60 * 60 * 24
                        self.request.session.set_expiry(1209600)
                        response = HttpResponse()
                        response.set_cookie('cid1', self.request.POST['email'], max_age=cookie_age)
                        response.set_cookie('cid2', self.request.POST['password'], max_age=cookie_age)
                        response.set_cookie('cid3', self.request.POST['remember_me'], max_age=cookie_age)
                        return response
                    else:
                        self.request.session.set_expiry(0)
                    return redirect('adminpanel:superadmin-dashboard"')
                if user_object.is_subadmin:
                    login(self.request, user_object)
                    messages.success(self.request, 'Logged in successfully')
                    if remember_me:
                        cookie_age = 60 * 60 * 24
                        self.request.session.set_expiry(1209600)
                        response = HttpResponse()
                        response.set_cookie('cid1', self.request.POST['email'], max_age=cookie_age)
                        response.set_cookie('cid2', self.request.POST['password'], max_age=cookie_age)
                        response.set_cookie('cid3', self.request.POST['remember_me'], max_age=cookie_age)
                        return response
                    else:
                        self.request.session.set_expiry(0)
                    return redirect('adminpanel:superadmin-dashboard"')
                else:
                    messages.error(self.request, "You are not authorised")
                    return HttpResponseRedirect(self.request.path_info, status=403)
            else:
                messages.error(self.request, "Incorrect Password")
                return HttpResponseRedirect(self.request.path_info, status=403)
        except Exception as e:
            messages.error(self.request, "Email doesn't exists")
            return HttpResponseRedirect(self.request.path_info, status=403)
        # return redirect("adminpanel:superadmin-dashboard")


class SuperAdminDashboard(LoginRequiredMixin, ListView):
    model = User
    template_name = "superadmin/dashboard.html"
    login_url = "adminpanel:superadmin"


class CustomerManagementView(LoginRequiredMixin, ListView):
    model = User
    template_name = "superadmin/customer-management.html"
    login_url = "adminpanel:superadmin"


class SuperAdminLogout(LoginRequiredMixin, View):
    model = User

    def get(self, request, *args, **kwargs):
        logout(self.request)
        return redirect("adminpanel:superadmin")


class PasswordChangeView(PasswordContextMixin, FormView):
    form_class = PasswordChangeForm
    success_url = reverse_lazy('adminpanel:superadmin-dashboard')
    login_url = "adminpanel:superadmin"
    title = _('Password change')

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        # Updating the password logs out all other sessions for the user
        # except the current one.
        update_session_auth_hash(self.request, form.user)
        messages.success(self.request, 'Password changed successfully')
        return super().form_valid(form)


class PasswordChangeDoneView(PasswordContextMixin, TemplateView):
    # template_name = 'registration/password_change_done.html'
    title = _('Password change successful')

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)


class SuperAdminSupscriptionView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/plan.html'
    login_url = "adminpanel:superadmin"


class SuperAdminClientsView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/clients.html'
    login_url = "adminpanel:superadmin"


class SuperAdminServiceProviders(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/provider.html'
    login_url = "adminpanel:superadmin"


class SuperAdminProvidersCategory(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/provider-category.html'


class SuperAdminAssaultFormView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/record_filed.html'
    login_url = "adminpanel:superadmin"


class SuperAdminAssaultRecords(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/assault-records.html'
    login_url = "adminpanel:superadmin"
