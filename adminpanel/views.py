import csv

from django.conf.global_settings import DEFAULT_FROM_EMAIL
from django.contrib import messages
from django.contrib.auth import login, logout, get_user_model, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordContextMixin
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
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

# from .filters import OrganizationFilter
from .forms import AdminLoginForm
from .models import User, Organization, SubscriptionPlan, SubscriptionStatus
from userapp.models import Survivor, ServiceProvider, Assault, ServiceProviderCategory

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
            print(e)
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


class SuperadminPasswordResetConfirmView(View):
    template_name = 'superadmin/new/superadmin_password_reset_confirm.html'

    # success_url = reverse_lazy('adminpanel:password_reset_complete')

    def get(self, request, *args, **kwargs):
        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if token_generator.check_token(user_object, token):
            return render(self.request, 'superadmin/new/superadmin_password_reset_confirm.html')
        else:
            messages.error(self.request, "Link is Invalid")
            return render(self.request, 'superadmin/new/superadmin_password_reset_confirm.html')

    def post(self, request, *args, **kwargs):

        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if not token_generator.check_token(user_object, token):
            messages.error(self.request, "Link is Invalid")
            return render(request, 'superadmin/new/superadmin_password_reset_confirm.html')

        password1 = self.request.POST.get('new_password1')
        password2 = self.request.POST.get('new_password2')

        if password1 != password2:
            messages.error(self.request, "Passwords do not match")
            return render(self.request, 'superadmin/new/superadmin_password_reset_confirm.html')
        elif len(password1) < 8:
            messages.error(
                self.request, "Password must be atleast 8 characters long")
            return render(request, 'superadmin/new/superadmin_password_reset_confirm.html')
        elif password1.isdigit() or password2.isdigit() or password1.isalpha() or password2.isalpha():
            messages.error(
                self.request, "Passwords must have a mix of numbers and characters")
            return render(request, 'superadmin/new/superadmin_password_reset_confirm.html')
        else:
            token = kwargs['token']
            user_id_b64 = kwargs['uidb64']
            uid = urlsafe_base64_decode(user_id_b64).decode()
            user_object = user.objects.get(id=uid)
            user_object.set_password(password1)
            user_object.save()
            return redirect('adminpanel:superadmin-password-reset-complete')


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
        if not user_qs[0].is_staff:
            messages.error(request, 'Unauthorised acces')
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


class SuperadminPasswordResetView(View):
    template_name = 'superadmin/new/superadmin_password_reset.html'

    def get(self, request, *args, **kwargs):
        return render(request, 'superadmin/new/superadmin_password_reset.html')

    def post(self, request, *args, **kwargs):
        user = get_user_model()
        email = request.POST.get('email')
        email_template = "superadmin/new/superadmin_password_reset_email.html"
        user_qs = user.objects.filter(email=email)
        if len(user_qs) == 0:
            messages.error(request, 'Email does not exists')
            return render(request, 'superadmin/new/superadmin_password_reset.html')
        if not user_qs[0].is_staff:
            messages.error(request, 'Unauthorised access')
            return render(request, 'superadmin/new/superadmin_password_reset.html')
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
            return redirect('adminpanel:superadmin-password-reset-done')
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
            return redirect('adminpanel:superadmin-password-reset-done')


class SuperAdminLogin(View):
    model = User
    template_name = 'superadmin/new/login.html'
    form_class = AdminLoginForm

    def get(self, request, *args, **kwargs):
        form = AdminLoginForm()
        try:
            if self.request.COOKIES.get('cid1') and self.request.COOKIES.get('cid2') and self.request.COOKIES.get(
                    'cid3'):
                return render(self.request, 'superadmin/new/login.html',
                              {'form': form, 'email': self.request.COOKIES.get('cid1'),
                               'password': self.request.COOKIES.get('cid2'),
                               'remember_me': self.request.COOKIES.get('cid3')})
            else:
                return render(self.request, 'superadmin/new/login.html', {'form': form})
        except:
            return render(self.request, 'superadmin/new/login.html', {'form': form})
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
            print(e)
            messages.error(self.request, "Email doesn't exists")
            return HttpResponseRedirect(self.request.path_info, status=403)
        # return redirect("adminpanel:superadmin-dashboard")


class SuperAdminDashboard(LoginRequiredMixin, ListView):
    model = Survivor
    template_name = "superadmin/new/dashboard.html"
    login_url = "adminpanel:superadmin"

    def get_context_data(self, *, object_list=None, **kwargs):
        context = super().get_context_data(**kwargs)
        context['survivors'] = User.objects.filter(is_survivor=True).count()
        context['service_providers'] = ServiceProvider.objects.all().count()
        context['assaults'] = Assault.objects.all().count()
        return context


class CustomerManagementView(LoginRequiredMixin, ListView):
    model = SubscriptionPlan
    template_name = "superadmin/new/customer-management.html"
    login_url = "adminpanel:superadmin"
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        subscription_plan_objects = None
        if self.request.GET.get('organization_name') and self.request.GET.get('from_date') and self.request.GET.get(
                'to_date'):
            subscription_plan_objects = SubscriptionStatus.objects.filter(
                Q(organization_name__organization_name__iexact=self.request.GET.get('organization_name')) |
                Q(organization_name__first_name__iexact=self.request.GET.get('first_name')) |
                Q(organization_name__email__iexact=self.request.GET.get('email')) |
                Q(organization_name__client_code__iexact=self.request.GET.get('client_code')) |
                Q(organization_name__mobile_number__iexact=self.request.GET.get('mobile_number')) |
                Q(organization_name__created_at__range=(
                    self.request.GET.get('from_date'), self.request.GET.get('to_date'))))
            print(subscription_plan_objects)
            if len(subscription_plan_objects) > 0:
                return render(self.request, 'superadmin/new/customer-management.html',
                              {'object_list': SubscriptionStatus.objects.all(), 'filter': subscription_plan_objects})
        elif self.request.GET.get('from_date') and self.request.GET.get(
                'to_date'):
            subscription_plan_objects = SubscriptionStatus.objects.filter(Q(organization_name__created_at__range=(
                self.request.GET.get('from_date'), self.request.GET.get('to_date'))))
            print('inside both date', subscription_plan_objects, subscription_plan_objects)
            if len(subscription_plan_objects) > 0:
                return render(self.request, 'superadmin/new/customer-management.html',
                              {'object_list': SubscriptionStatus.objects.all(), 'filter': subscription_plan_objects})
            else:
                return render(self.request, 'superadmin/new/customer-management.html',
                              {'object_list': SubscriptionStatus.objects.all(),
                               'no_data': 'subscription_plan_objects'})
        elif self.request.GET.get('from_date') or self.request.GET.get('to_date'):
            d = None
            if self.request.GET.get('from_date'):
                d = self.request.GET.get('from_date')
            else:
                self.request.GET.get('to_date')
            subscription_plan_objects = SubscriptionStatus.objects.filter(Q(organization_name__created_at__date=d))
            print(subscription_plan_objects)
            if len(subscription_plan_objects) > 0:
                return render(self.request, 'superadmin/new/customer-management.html',
                              {'object_list': SubscriptionStatus.objects.all(), 'filter': subscription_plan_objects})
            else:
                return render(self.request, 'superadmin/new/customer-management.html',
                              {'object_list': SubscriptionStatus.objects.all(),
                               'no_data': 'subscription_plan_objects'})
        elif self.request.GET.get('organization_name') or self.request.GET.get('first_name') or self.request.GET.get(
                'email') or self.request.GET.get('client_code') or self.request.GET.get('mobile_number'):
            subscription_plan_objects = SubscriptionStatus.objects.filter(
                Q(organization_name__organization_name__iexact=self.request.GET.get('organization_name')) |
                Q(organization_name__first_name__iexact=self.request.GET.get('first_name')) |
                Q(organization_name__email__iexact=self.request.GET.get('email')) |
                Q(organization_name__client_code__iexact=self.request.GET.get('client_code')) |
                Q(organization_name__mobile_number__iexact=self.request.GET.get(
                    'mobile_number')
                ))
            if len(subscription_plan_objects) > 0:
                return render(self.request, 'superadmin/new/customer-management.html',
                              {'object_list': SubscriptionStatus.objects.all(), 'filter': subscription_plan_objects})
            else:
                print('inside else')
                return render(self.request, 'superadmin/new/customer-management.html',
                              {'object_list': SubscriptionStatus.objects.all(), 'no_data': 'subscription_plan_objects'})
        else:
            organizations = SubscriptionStatus.objects.all().order_by('-id')
            paginator = Paginator(organizations, self.paginate_by)
            page_number = self.request.GET.get('page')
            page_obj = paginator.get_page(page_number)
            context = {
                'object_list': SubscriptionStatus.objects.all(),
                'pages': page_obj
                # 'page_obj': page_obj
            }
            return render(self.request, 'superadmin/new/customer-management.html', context)


class CustomerManagementDetailView(View):
    model = Organization
    login_url = "adminpanel:superadmin"
    paginate_by = 1

    def post(self, request, *args, **kwargs):
        organization_obj = Organization.objects.get(id=self.request.POST.get('id'))
        return JsonResponse({'organization_name': organization_obj.organization_name,
                             'first_name': organization_obj.first_name,
                             'last_name': organization_obj.last_name,
                             'email': organization_obj.email,
                             'mobile_number': organization_obj.mobile_number
                             }, status=200)


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


class SuperAdminBrasiSupscriptionView(LoginRequiredMixin, ListView):
    model = SubscriptionPlan
    template_name = 'superadmin/new/brasi-plan.html'
    login_url = "adminpanel:superadmin"
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        subs_obj = None
        if self.request.GET.get('category') and self.request.GET.get('from'):
            subs_obj = SubscriptionPlan.objects.filter(
                Q(category__iexact=self.request.GET.get('category' or None)) |
                Q(name__iexact=self.request.GET.get('name' or None)) |
                Q(duration__iexact=self.request.GET.get('duration' or None)) |
                Q(price__iexact=self.request.GET.get('price' or None)) |
                Q(active__iexact=self.request.GET.get('active')) |
                Q(created_at__range=(self.request.GET.get('from' or None), self.request.GET.get('to' or None))))
            return render(self.request, "superadmin/new/brasi-plan.html",
                          {'subs_obj': subs_obj.exclude(plan_type='General Subscription Plans')})
        elif self.request.GET.get('from') and self.request.GET.get('to'):
            subs_obj = SubscriptionPlan.objects.filter(
                Q(created_at__date__range=(self.request.GET.get('from'), self.request.GET.get('to'))))
            return render(self.request, "superadmin/new/brasi-plan.html",
                          {'subs_obj': subs_obj.exclude(plan_type='General Subscription Plans')})
        elif self.request.GET.get('from'):
            subs_obj = SubscriptionPlan.objects.filter(
                Q(created_at__date=self.request.GET.get('from')))
            return render(self.request, "superadmin/new/brasi-plan.html",
                          {'subs_obj': subs_obj.exclude(plan_type='General Subscription Plans')})
        elif self.request.GET.get('to'):
            subs_obj = SubscriptionPlan.objects.filter(
                Q(created_at__date=self.request.GET.get('to')))
            return render(self.request, "superadmin/new/brasi-plan.html",
                          {'subs_obj': subs_obj.exclude(plan_type='General Subscription Plans')})
        elif self.request.GET.get('category') or self.request.GET.get('name') or self.request.GET.get(
                'duration') or self.request.GET.get('price') or self.request.GET.get('active'):
            subs_obj = SubscriptionPlan.objects.filter(
                Q(category__iexact=self.request.GET.get('category' or None)) |
                Q(name__iexact=self.request.GET.get('name' or None)) |
                Q(duration__iexact=self.request.GET.get('duration' or None)) |
                Q(price__iexact=self.request.GET.get('price' or None)) |
                Q(active__iexact=self.request.GET.get('active')))

            return render(self.request, "superadmin/new/brasi-plan.html",
                          {'subs_obj': subs_obj.exclude(plan_type='General Subscription Plans')})
        else:
            organizations = SubscriptionPlan.objects.filter(plan_type='Brasi Platform').order_by('-id')
            paginator = Paginator(organizations, self.paginate_by)
            page_number = self.request.GET.get('page')
            page_obj = paginator.get_page(page_number)
            context = {
                'object_list': SubscriptionPlan.objects.filter(plan_type='Brasi Platform'),
                'pages': page_obj,
            }
            return render(self.request, "superadmin/new/brasi-plan.html", context)


class SubscriptionBrasiPlanDetail(View):
    model = SubscriptionPlan
    template_name = 'superadmin/new/brasi-plan.html'
    login_url = "adminpanel:superadmin"
    paginate_by = 1

    def post(self, request, *args, **kwargs):
        organizations = SubscriptionPlan.objects.get(id=self.request.POST.get('id'))
        return JsonResponse(
            {'category': organizations.category, 'name': organizations.name, 'price': organizations.price,
             'description': organizations.description, 'duration': organizations.duration,
             'number_of_persons': organizations.number_of_persons}, status=200)


class SuperAdminGeneralSupscriptionView(LoginRequiredMixin, ListView):
    model = SubscriptionPlan
    template_name = 'superadmin/new/general-plan.html'
    login_url = "adminpanel:superadmin"
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        print(self.request.GET)
        subs_obj = None
        if self.request.GET.get('category') and self.request.GET.get('from'):
            subs_obj = SubscriptionPlan.objects.filter(
                Q(category__iexact=self.request.GET.get('category' or None)) |
                Q(name__iexact=self.request.GET.get('name' or None)) |
                Q(duration__iexact=self.request.GET.get('duration' or None)) |
                Q(price__iexact=self.request.GET.get('price' or None)) |
                Q(active__iexact=self.request.GET.get('active')) |
                Q(created_at__range=(self.request.GET.get('from' or None), self.request.GET.get('to' or None))))
            print(subs_obj)
            return render(self.request, "superadmin/new/general-plan.html",
                          {'subs_obj': subs_obj.exclude(plan_type='Brasi Platform')})
        elif self.request.GET.get('from') and self.request.GET.get('to'):
            subs_obj = SubscriptionPlan.objects.filter(
                Q(created_at__date__range=(self.request.GET.get('from'), self.request.GET.get('to'))))
            return render(self.request, "superadmin/new/general-plan.html",
                          {'subs_obj': subs_obj.exclude(plan_type='Brasi Platform')})
        elif self.request.GET.get('from'):
            subs_obj = SubscriptionPlan.objects.filter(
                Q(created_at__date=self.request.GET.get('from')))
            return render(self.request, "superadmin/new/general-plan.html",
                          {'subs_obj': subs_obj.exclude(plan_type='Brasi Platform')})
        elif self.request.GET.get('to'):
            subs_obj = SubscriptionPlan.objects.filter(
                Q(created_at__date=self.request.GET.get('to')))
            return render(self.request, "superadmin/new/general-plan.html",
                          {'subs_obj': subs_obj.exclude(plan_type='Brasi Platform')})

        elif self.request.GET.get('category') or self.request.GET.get('name') or self.request.GET.get(
                'duration') or self.request.GET.get('price') or self.request.GET.get('active'):
            subs_obj = SubscriptionPlan.objects.filter(
                Q(category__iexact=self.request.GET.get('category' or None)) |
                Q(name__iexact=self.request.GET.get('name' or None)) |
                Q(duration__iexact=self.request.GET.get('duration' or None)) |
                Q(price__iexact=self.request.GET.get('price' or None)) |
                Q(active__iexact=self.request.GET.get('active')))
            return render(self.request, "superadmin/new/general-plan.html",
                          {'subs_obj': subs_obj.exclude(plan_type='Brasi Platform')})
        else:
            organizations = SubscriptionPlan.objects.filter(plan_type='General Subscription Plans').order_by('-id')
            paginator = Paginator(organizations, self.paginate_by)
            page_number = self.request.GET.get('page')
            page_obj = paginator.get_page(page_number)
            context = {
                'object_list': SubscriptionPlan.objects.filter(plan_type='General Subscription Plans'),
                'pages': page_obj,
            }
            return render(self.request, "superadmin/new/general-plan.html", context)


class SubscriptionGeneralPlanDetail(View):
    model = SubscriptionPlan
    template_name = 'superadmin/new/general-plan.html'
    login_url = "adminpanel:superadmin"
    paginate_by = 1

    def post(self, request, *args, **kwargs):
        organizations = SubscriptionPlan.objects.get(id=self.request.POST.get('id'))
        return JsonResponse(
            {'category': organizations.category, 'name': organizations.name, 'price': organizations.price,
             'description': organizations.description, 'duration': organizations.duration,
             'number_of_persons': organizations.number_of_persons}, status=200)


class CreateSubscriptionPlan(View):
    model = SubscriptionPlan

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        plan_type = ' '.join(self.request.POST['plan_type'].split('_'))
        inactive = self.request.POST['check'].title()
        print(inactive)
        check = None
        if inactive == 'True':
            check = False
        else:
            check = True
        print(check)
        SubscriptionPlan.objects.create(
            plan_type=plan_type,
            category=self.request.POST['category'],
            name=self.request.POST['name'],
            description=self.request.POST['description'],
            duration=self.request.POST['duration'],
            price=self.request.POST['price'],
            number_of_persons=self.request.POST['number_of_persons'],
            active=check,
        )
        messages.success(self.request, 'Subscription plan added successfully')
        return redirect("adminpanel:superadmin-subscription-plan")


class CreateGeneralSubscriptionPlan(View):
    model = SubscriptionPlan

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        plan_type = ' '.join(self.request.POST['plan_type'].split('_'))
        inactive = self.request.POST['check'].title()
        print(inactive)
        check = None
        if inactive == 'True':
            check = False
        else:
            check = True
        print(check)
        SubscriptionPlan.objects.create(
            plan_type=plan_type,
            category=self.request.POST['category'],
            name=self.request.POST['name'],
            description=self.request.POST['description'],
            duration=self.request.POST['duration'],
            price=self.request.POST['price'],
            number_of_persons=self.request.POST['number_of_persons'],
            active=check,
        )
        messages.success(self.request, 'Subscription plan added successfully')
        return redirect("adminpanel:superadmin-general-subscription-plan")


class EditSubscriptionPlan(View):
    model = SubscriptionPlan

    def post(self, request, *args, **kwargs):
        print('From edit subscription plan', self.request.POST)
        plan_type = ' '.join(self.request.POST['plan_type'].split('_'))
        subs_obj = SubscriptionPlan.objects.get(id=self.request.POST['obj_id'])
        subs_obj.plan_type = plan_type
        subs_obj.category = self.request.POST['category']
        subs_obj.name = self.request.POST['name']
        subs_obj.description = self.request.POST['description']
        subs_obj.duration = self.request.POST['duration']
        subs_obj.price = self.request.POST['price']
        subs_obj.number_of_persons = self.request.POST['number_of_persons']
        subs_obj.active = self.request.POST['check'].title()
        subs_obj.save()
        print(subs_obj)
        messages.success(self.request, 'Subscription plan updated successfully')
        return redirect("adminpanel:superadmin-subscription-plan")


class EditServiceCategory(View):
    model = SubscriptionPlan

    def post(self, request, *args, **kwargs):
        print('From edit subscription plan', self.request.POST)
        subs_obj = ServiceProviderCategory.objects.get(id=self.request.POST['obj_id'])
        subs_obj.category_name = self.request.POST['category']
        subs_obj.active = self.request.POST['check'].title()
        subs_obj.save()
        print(subs_obj)
        messages.success(self.request, 'Service provider category updated successfully')
        return redirect("adminpanel:superadmin-service-providers-category")


class EditGeneralSubscriptionPlan(View):
    model = SubscriptionPlan

    def post(self, request, *args, **kwargs):
        print('From edit subscription plan', self.request.POST)
        plan_type = ' '.join(self.request.POST['plan_type'].split('_'))
        subs_obj = SubscriptionPlan.objects.get(id=self.request.POST['obj_id'])
        subs_obj.plan_type = plan_type
        subs_obj.category = self.request.POST['category']
        subs_obj.name = self.request.POST['name']
        subs_obj.description = self.request.POST['description']
        subs_obj.duration = self.request.POST['duration']
        subs_obj.price = self.request.POST['price']
        subs_obj.number_of_persons = self.request.POST['number_of_persons']
        subs_obj.active = self.request.POST['check'].title()
        subs_obj.save()
        print(subs_obj)
        messages.success(self.request, 'Subscription plan updated successfully')
        return redirect("adminpanel:superadmin-general-subscription-plan")


class SuperAdminClientsView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/clients.html'
    login_url = "adminpanel:superadmin"


class SuperAdminServiceProviders(LoginRequiredMixin, ListView):
    model = ServiceProvider
    template_name = 'superadmin/new/provider.html'
    login_url = "adminpanel:superadmin"


class SuperAdminProvidersCategory(LoginRequiredMixin, ListView):
    model = ServiceProviderCategory
    template_name = 'superadmin/new/provider-category.html'
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        print(self.request.GET.get('category_name'))
        print(self.request.GET.get('from_date'))
        print(self.request.GET.get('to_date'))
        # if self.request.GET.get('')
        if self.request.GET.get('category_name') and self.request.GET.get('to_date') and self.request.GET.get(
                'from_date'):
            category_obj = ServiceProviderCategory.objects.filter(
                Q(category_name=self.request.GET.get('category_name')) &
                Q(created_at__date__range=(self.request.GET.get('from_date'),
                                           self.request.GET.get('to_date'))))
            print('BOTH--', category_obj)
            return render(self.request, 'superadmin/new/provider-category.html',
                          {'object_list': category_obj})
        elif self.request.GET.get('to_date') and self.request.GET.get('from_date'):
            category_obj = ServiceProviderCategory.objects.filter(
                Q(created_at__date__range=(self.request.GET.get('from_date'), self.request.GET.get('to_date'))))
            print('both date--', category_obj)
            return render(self.request, 'superadmin/new/provider-category.html',
                          {'object_list': category_obj})
        elif self.request.GET.get('category_name'):
            category_obj = ServiceProviderCategory.objects.filter(category_name=self.request.GET.get('category_name'))
            return render(self.request, 'superadmin/new/provider-category.html',
                          {'object_list': category_obj})
        elif self.request.GET.get('from_date'):
            category_obj = ServiceProviderCategory.objects.filter(Q(created_at__date=self.request.GET.get('from_date')))
            return render(self.request, 'superadmin/new/provider-category.html',
                          {'object_list': category_obj})
        elif self.request.GET.get('to_date'):
            category_obj = ServiceProviderCategory.objects.filter(Q(created_at__date=self.request.GET.get('to_date')))
            return render(self.request, 'superadmin/new/provider-category.html',
                          {'object_list': category_obj})
        else:
            print('inside else')
            category_obj = ServiceProviderCategory.objects.all()
            paginator = Paginator(category_obj, self.paginate_by)
            page_number = self.request.GET.get('page')
            page_obj = paginator.get_page(page_number)
            return render(self.request, 'superadmin/new/provider-category.html',
                          {'object_list': category_obj, 'pages': page_obj, })


class SuperAdminAssaultFormView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/record_filed.html'
    login_url = "adminpanel:superadmin"


class SuperAdminAssaultRecords(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/assault-records.html'
    login_url = "adminpanel:superadmin"


class CMSBenefits(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/benefits.html'
    login_url = "adminpanel:superadmin"


class CMSFeature(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/features.html'
    login_url = "adminpanel:superadmin"


class CMSHowItWorks(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/how_it_work.html'
    login_url = "adminpanel:superadmin"


class CMSSocialPages(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/social.html'
    login_url = "adminpanel:superadmin"


class CMSPrivacyPolicy(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/privacy.html'
    login_url = "adminpanel:superadmin"


class CMSTermsOfUse(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/terms.html'
    login_url = "adminpanel:superadmin"


class FaqSurvivors(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/faq-survivors.html'
    login_url = "adminpanel:superadmin"


class FaqService(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/faq-service.html'
    login_url = "adminpanel:superadmin"


class FaqLicense(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/faq-license.html'
    login_url = "adminpanel:superadmin"


class ReportSurvivor(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/report-service.html'
    login_url = "adminpanel:superadmin"


class ReportServiceProvider(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/report-survivor.html'
    login_url = "adminpanel:superadmin"


class VoucherView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/voucher.html'
    login_url = "adminpanel:superadmin"


class SpecialUserView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/user.html'
    login_url = "adminpanel:superadmin"


class MailBoxView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/mailbox.html'
    login_url = "adminpanel:superadmin"


class SuperAdminNotifications(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/notification.html'
    login_url = "adminpanel:superadmin"


class CreateOrganization(View):
    model = Organization
    template_name = 'superadmin/new/customer-management.html'

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        # return redirect("adminpanel:customer-management")
        organization_name = self.request.POST['organization_name']
        first_name = self.request.POST['first_name']
        last_name = self.request.POST['last_name']
        mobile_number = self.request.POST['mobile_number']
        email = self.request.POST['email']
        inactive = self.request.POST['check'].title()
        print(inactive)
        check = None
        if inactive == 'True':
            check = False
        else:
            check = True
        print(check)
        try:
            try:
                organization_by_name = Organization.objects.get(Q(organization_name=organization_name) | Q(email=email))
                print(organization_by_name)
                # organization_by_email = Organization.objects.get(email=email)
                # if organization_by_name or organization_by_email:
                return JsonResponse({'message': 'Organization with this name/email already exists'}, status=400)
            except Exception as e:
                print(e)
                org = Organization.objects.create(organization_name=organization_name, first_name=first_name,
                                                  last_name=last_name,
                                                  mobile_number=mobile_number, email=email, active=check)
                SubscriptionStatus.objects.create(organization_name=org)
                messages.success(self.request, "Organization created successfully")
                return redirect("adminpanel:customer-management")
        except Exception as e:
            return JsonResponse({'message': str(e)}, status=400)


class EditOrganization(View):
    model = Organization

    def post(self, request, *args, **kwargs):
        print('From Edit organization--', self.request.POST)
        print(args)
        print(kwargs)
        try:
            organization_by_name = Organization.objects.filter(Q(email=self.request.POST['edit_email']) | Q(
                organization_name=self.request.POST['edit_organization_name'])).first()
            print(organization_by_name)
            if (organization_by_name and organization_by_name.organization_name != self.request.POST[
                'edit_organization_name']) or organization_by_name and organization_by_name.email != self.request.POST[
                'edit_email']:
                return JsonResponse(
                    {'message': 'Organization with email/name already exists. Please supply different values'},
                    status=400)
            else:
                organization_obj = Organization.objects.get(id=self.request.POST['obj_id'])
                organization_obj.organization_name = self.request.POST['edit_organization_name']
                organization_obj.first_name = self.request.POST['edit_first_name']
                organization_obj.last_name = self.request.POST['edit_last_name']
                organization_obj.email = self.request.POST['edit_email']
                organization_obj.mobile_number = self.request.POST['edit_mobile_number']
                organization_obj.save()
                return redirect("adminpanel:customer-management")
        except Exception as e:
            print('Exception', e)
            organization_obj = Organization.objects.get(id=self.request.POST['obj_id'])
            organization_obj.organization_name = self.request.POST['edit_organization_name']
            organization_obj.first_name = self.request.POST['edit_first_name']
            organization_obj.last_name = self.request.POST['edit_last_name']
            organization_obj.email = self.request.POST['edit_email']
            organization_obj.mobile_number = self.request.POST['edit_mobile_number']
            organization_obj.save()
            return redirect("adminpanel:customer-management")


class DeleteOrganization(View):
    model = Organization

    def get(self, request, *args, **kwargs):
        organization_obj = Organization.objects.get(id=kwargs['pk'])
        organization_obj.delete()
        messages.success(self.request, "Organization deleted successfully")
        return redirect("adminpanel:customer-management")


class DeleteSubscriptionPlan(View):
    model = SubscriptionPlan

    def get(self, request, *args, **kwargs):
        organization_obj = SubscriptionPlan.objects.get(id=kwargs['pk'])
        organization_obj.delete()
        messages.success(self.request, "Subscription plan deleted successfully")
        return redirect("adminpanel:superadmin-subscription-plan")


class DeleteServiceProviderCategory(View):
    model = ServiceProviderCategory

    def get(self, request, *args, **kwargs):
        organization_obj = ServiceProviderCategory.objects.get(id=kwargs['pk'])
        organization_obj.delete()
        messages.success(self.request, "Service provider category deleted successfully")
        return redirect("adminpanel:superadmin-service-providers-category")


class DeleteGeneralSubscriptionPlan(View):
    model = SubscriptionPlan

    def get(self, request, *args, **kwargs):
        print('inside delete general subscription plan')
        organization_obj = SubscriptionPlan.objects.get(id=kwargs['pk'])
        organization_obj.delete()
        messages.success(self.request, "Subscription plan deleted successfully")
        return redirect("adminpanel:superadmin-general-subscription-plan")


class ExportOrganizationDataView(LoginRequiredMixin, View):
    model = Organization
    login_url = 'adminpanel:superadmin'

    def get(self, request, *args, **kwargs):
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="organization.csv"'
        writer = csv.writer(response)
        writer.writerow(
            ['Organization Id', 'Organization Name', 'First Name', 'Last Name', 'Email', 'Mobile Number', 'Client Code',
             'active', 'created_at'])
        organizations = Organization.objects.all().values_list('id', 'organization_name', 'first_name',
                                                               'last_name', 'email', 'mobile_number', 'client_code',
                                                               'active', 'created_at').order_by('-id')
        for organization in organizations:
            writer.writerow(organization)
        return response


class ExportSubscriptionPlanDataView(LoginRequiredMixin, View):
    model = SubscriptionPlan
    login_url = 'adminpanel:superadmin'

    def get(self, request, *args, **kwargs):
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="subscriptionplans.csv"'
        writer = csv.writer(response)
        writer.writerow(
            ['Subscription Id', 'Plan Type', 'Category', 'Name', 'Description', 'Price', 'Duration',
             'No Of Users Allowed', 'Platform', 'Subscription Status', 'created_at'])
        subscriptions = SubscriptionPlan.objects.all().values_list('id', 'plan_type', 'category',
                                                                   'name', 'description', 'price', 'duration',
                                                                   'number_of_persons', 'platform', 'active',
                                                                   'created_at')
        for subscription in subscriptions:
            writer.writerow(subscription)
        return response


class ExportServiceProviderCategoryView(LoginRequiredMixin, View):
    model = ServiceProviderCategory
    login_url = 'adminpanel:superadmin'

    def get(self, request, *args, **kwargs):
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="category.csv"'
        writer = csv.writer(response)
        writer.writerow(
            ['Category Id', 'Category Name', 'created_at'])
        categories = ServiceProviderCategory.objects.all().values_list('id', 'category_name', 'created_at__date')
        for category in categories:
            writer.writerow(category)
        return response


class InactiveOrganization(LoginRequiredMixin, View):
    model = Organization

    def get(self, request, *args, **kwargs):
        obj = Organization.objects.get(id=kwargs['pk'])
        if obj.active:
            obj.active = False
            obj.save()
        else:
            obj.active = True
            obj.save()
        return redirect("adminpanel:customer-management")


class InactiveSubscriptionPlan(LoginRequiredMixin, View):
    model = SubscriptionPlan

    def get(self, request, *args, **kwargs):
        print(kwargs)
        obj = SubscriptionPlan.objects.get(id=kwargs['pk'])
        if obj.active:
            obj.active = False
            obj.save()
        else:
            obj.active = True
            obj.save()
        return redirect("adminpanel:superadmin-subscription-plan")


class InactiveServiceProviderCategory(LoginRequiredMixin, View):
    model = ServiceProviderCategory

    def get(self, request, *args, **kwargs):
        print(kwargs)
        obj = ServiceProviderCategory.objects.get(id=kwargs['pk'])
        if obj.active:
            obj.active = False
            obj.save()
        else:
            obj.active = True
            obj.save()
        return redirect("adminpanel:superadmin-service-providers-category")


class InactiveSubscriptionPlan2(LoginRequiredMixin, View):
    model = SubscriptionPlan

    def get(self, request, *args, **kwargs):
        print(kwargs)
        obj = SubscriptionPlan.objects.get(id=kwargs['pk'])
        if obj.active:
            obj.active = False
            obj.save()
        else:
            obj.active = True
            obj.save()
        return redirect("adminpanel:superadmin-general-subscription-plan")


class SubscriptionDetailView(View):
    model = SubscriptionPlan

    def post(self, request, *args, **kwargs):
        print(kwargs)
        print(self.request.POST)
        # return render(self.request, 'superadmin/new/brasi-plan.html',
        #               {'object': SubscriptionPlan.objects.get(id=self.request.POST['id'])})
        subs_obj = SubscriptionPlan.objects.get(id=self.request.POST['id'])
        d = []
        d.append({'plan_type': subs_obj.plan_type})
        d.append({'category': subs_obj.category})
        d.append({'name': subs_obj.name})
        d.append({'description': subs_obj.description})
        d.append({'price': subs_obj.price})
        d.append({'duration': subs_obj.duration})
        d.append({'number_of_persons': subs_obj.number_of_persons})
        d.append({'platform': subs_obj.platform})
        d.append({'active': subs_obj.active})
        d.append({'created_at': subs_obj.created_at})
        return JsonResponse({'plan_type': subs_obj.plan_type, 'category': subs_obj.category, 'name': subs_obj.name,
                             'description': subs_obj.description, 'price': subs_obj.price,
                             'duration': subs_obj.duration, 'number_of_persons': subs_obj.number_of_persons,
                             'platform': subs_obj.platform, 'active': subs_obj.active,
                             'created_at': subs_obj.created_at},
                            status=200)


class ServiceProviderCategoryDetailView(View):
    model = ServiceProviderCategory

    def post(self, request, *args, **kwargs):
        print(kwargs)
        print(self.request.POST)
        subs_obj = ServiceProviderCategory.objects.get(id=self.request.POST['id'])
        d = []
        d.append({'category': subs_obj.category_name})
        d.append({'active': subs_obj.active})

        return JsonResponse({'category': subs_obj.category_name, 'active': subs_obj.active},
                            status=200)


class HeroView(View):
    template_name = 'superadmin/new/hero.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'superadmin/new/hero.html')


class AddServiceProviderCategory(View):
    model = ServiceProviderCategory

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        checked = None
        if self.request.POST.get('status').title():
            checked = False
        if self.request.POST.get('status') == 'false':
            checked = True
        print(checked)
        ServiceProviderCategory.objects.create(
            category_name=self.request.POST.get('category_name'),
            active=checked
        )
        return JsonResponse({'message': 'Service provider category created'}, status=200)
