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
            messages.error(self.request, "Email doesn't exists")
            return HttpResponseRedirect(self.request.path_info, status=403)
        # return redirect("adminpanel:superadmin-dashboard")


class SuperAdminDashboard(LoginRequiredMixin, ListView):
    model = User
    template_name = "superadmin/new/dashboard.html"
    login_url = "adminpanel:superadmin"


class CustomerManagementView(LoginRequiredMixin, ListView):
    model = SubscriptionPlan
    template_name = "superadmin/new/customer-management.html"
    login_url = "adminpanel:superadmin"
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        if self.request.GET.get('organization_name'):
            subscription_plan_objects = SubscriptionStatus.objects.filter(
                Q(organization_name__organization_name__iexact=self.request.GET['organization_name']) |
                Q(organization_name__first_name__iexact=self.request.GET['first_name']) |
                Q(organization_name__email__iexact=self.request.GET['email']) |
                Q(organization_name__client_code__iexact=self.request.GET['client_code']) |
                Q(organization_name__created_at__range=(self.request.GET['from_date'], self.request.GET['to_date'])))
            if len(subscription_plan_objects) > 0:
                return render(self.request, 'superadmin/new/customer-management.html',
                              {'object_list': SubscriptionStatus.objects.all(), 'filter': subscription_plan_objects})
            else:

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
    model = SubscriptionPlan
    template_name = 'superadmin/new/plan.html'
    login_url = "adminpanel:superadmin"
    paginate_by = 1

    def get(self, request, *args, **kwargs):
        print(self.request.GET)
        if self.request.GET.get('category'):
            subs_obj = SubscriptionPlan.objects.filter(
                Q(category__iexact=self.request.GET.get('category' or None)) |
                Q(name__iexact=self.request.GET.get('name' or None)) |
                Q(duration__iexact=self.request.GET.get('duration' or None)) |
                Q(price__iexact=self.request.GET.get('price' or None)) |
                Q(active__iexact=self.request.GET.get('active')) |
                Q(created_at__range=(self.request.GET.get('from' or None), self.request.GET.get('to' or None))))
            print(subs_obj)
            return render(self.request, "superadmin/new/plan.html",
                          {'subs_obj': subs_obj.exclude(plan_type='General Subscription Plans'),
                           'object_list2': SubscriptionPlan.objects.filter(plan_type='General Subscription Plans')})
        elif self.request.GET.get('category2'):
            subs_obj2 = SubscriptionPlan.objects.filter(
                Q(category__iexact=self.request.GET.get('category2' or None)) |
                Q(name__iexact=self.request.GET.get('name2' or None)) |
                Q(duration__iexact=self.request.GET.get('duration2' or None)) |
                Q(price__iexact=self.request.GET.get('price2' or None)) |
                Q(active__iexact=self.request.GET.get('active2' or None)) |
                Q(created_at__range=(self.request.GET.get('from2'), self.request.GET.get('to2'))))
            print('---->>>', subs_obj2)
            return render(self.request, "superadmin/new/plan.html",
                          {'subs_obj2': subs_obj2.exclude(plan_type='Brasi Platform'),
                           'object_list2': SubscriptionPlan.objects.filter(plan_type='General Subscription Plans')})
        else:
            organizations = SubscriptionPlan.objects.filter(plan_type='Brasi Platform').order_by('-id')
            paginator = Paginator(organizations, self.paginate_by)
            page_number = self.request.GET.get('page')
            page_obj = paginator.get_page(page_number)
            organizations = SubscriptionPlan.objects.filter(plan_type='General Subscription Plans').order_by('-id')
            paginator = Paginator(organizations, self.paginate_by)
            page_number = self.request.GET.get('page')
            page_obj_2 = paginator.get_page(page_number)
            context = {
                'object_list': SubscriptionPlan.objects.filter(plan_type='Brasi Platform'),
                'object_list2': SubscriptionPlan.objects.filter(plan_type='General Subscription Plans'),
                'pages': page_obj,
                'pages_2': page_obj_2
                # 'page_obj': page_obj
            }
            return render(self.request, "superadmin/new/plan.html", context)


class CreateSubscriptionPlan(View):
    model = SubscriptionPlan

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        plan_type = ' '.join(self.request.POST['plan_type'].split('_'))
        SubscriptionPlan.objects.create(
            plan_type=plan_type,
            category=self.request.POST['category'],
            name=self.request.POST['name'],
            description=self.request.POST['description'],
            duration=self.request.POST['duration'],
            price=self.request.POST['price'],
            number_of_persons=self.request.POST['number_of_persons'],
            active=self.request.POST['check'].title(),
        )
        messages.success(self.request, 'Subscription plan added successfully')
        return redirect("adminpanel:superadmin-subscription-plan")


class SuperAdminClientsView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/clients.html'
    login_url = "adminpanel:superadmin"


class SuperAdminServiceProviders(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/provider.html'
    login_url = "adminpanel:superadmin"


class SuperAdminProvidersCategory(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/provider-category.html'


class SuperAdminAssaultFormView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/record_filed.html'
    login_url = "adminpanel:superadmin"


class SuperAdminAssaultRecords(LoginRequiredMixin, ListView):
    model = User
    template_name = 'superadmin/new/assault-records.html'
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
        check = self.request.POST['check']
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
                                                  mobile_number=mobile_number, email=email, active=check.title())
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
            organization_by_name = Organization.objects.get(Q(email=self.request.POST['edit_email']) | Q(
                organization_name=self.request.POST['edit_organization_name']))
            print(organization_by_name)
            return JsonResponse(
                {'message': 'Organization with email/name already exists. Please supply different values'},
                status=400)
        except Exception as e:
            print('Exception', e)
            organization_obj = Organization.objects.get(id=self.request.POST['obj_id'])
            organization_obj.organization_name = self.request.POST['edit_organization_name']
            organization_obj.first_name = self.request.POST['edit_first_name']
            organization_obj.last_name = self.request.POST['edit_last_name']
            organization_obj.email = self.request.POST['edit_email']
            organization_obj.mobile_number = self.request.POST['edit_email']
            organization_obj.save()
            return redirect("adminpanel:customer-management")
