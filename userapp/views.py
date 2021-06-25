import json
from datetime import datetime
from decimal import Decimal

from adminpanel.views import User
from django.conf.global_settings import DEFAULT_FROM_EMAIL
from django.contrib import messages
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.http import JsonResponse
from django.shortcuts import render, HttpResponse, redirect
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views.generic import View, ListView, CreateView

from .forms import SurvivorSignUpForm, AssaultForm, AssaultQuestionAnswerForm, SurvivorLoginByEmailForm
from .models import Survivor, Assault, AssaultQuestionAnswer, Faq, Contact, Notification, ServiceProvider, \
    ServiceProviderSlots

user = get_user_model()


class HomeView(View):
    template_name = 'userapp/index.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/index.html')


class GuestAssaultUser(View):
    template_name = 'userapp/guest_record_from1.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/guest_record_from1.html')


class GuestAssaultUserForm2View(View):
    template_name = 'userapp/guest_assault_form_2.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/guest_assault_form_2.html')


class SurvivorSignUp(CreateView):
    model = Survivor
    form_class = SurvivorSignUpForm
    template_name = 'userapp/index.html'

    def post(self, request, *args, **kwargs):
        user_email = User.objects.filter(email=self.request.POST['email']).count()
        user_phone = User.objects.filter(phone_number=self.request.POST['mobile_number']).count()
        if user_email > 0 and user_phone > 0:
            return JsonResponse(
                {
                    'message': 'This phone number and email address is already in use. Please supply a different phone number and email address.'},
                status=400)
        elif user_email > 0:
            return JsonResponse(
                {'message': 'This email address is already in use. Please supply a different email address'},
                status=400)
        elif user_phone > 0:
            return JsonResponse(
                {'message': 'This phone number is already in use. Please supply a different phone number address.'},
                status=400)
        else:
            # print(self.request.POST)
            # user = User.objects.create(
            #     email=self.request.POST['email'],
            #     phone_number=self.request.POST['mobile_number'],
            #     is_survivor=True
            # )
            # user.set_password(self.request.POST['password'])
            # user.save()
            # survivor = Survivor.objects.create(
            #     user=user,
            #     client_code=self.request.POST['client_code'],
            #     consent=self.request.POST['check']
            # )
            return HttpResponse('Survivor created')

    # def form_valid(self, form):
    #     try:
    #         user = User.objects.get(email=form.cleaned_data['email'])
    #         print(user)
    #         return HttpResponseRedirect(self.request.path_info, status=403)
    #     except Exception as e:
    #         print('Exception', e)
    #         return HttpResponseRedirect(self.request.path_info, status=200)
    #
    # def form_invalid(self, form):
    #     return self.render_to_response(self.get_context_data(form=form))


class CompleteSurvivorSignUp(View):
    model = User
    template_name = 'userapp/index.html'

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        user = User.objects.create(
            email=self.request.POST['email'],
            phone_number=self.request.POST['mobile_number'],
            first_name=self.request.POST['first_name'],
            last_name=self.request.POST['last_name'],
            nick_name=self.request.POST['nick_name'],
            is_survivor=True
        )
        user.set_password(self.request.POST['password'])
        user.save()
        survivor = Survivor.objects.create(
            user=user,
            client_code=self.request.POST['client_code'],
            consent=self.request.POST['check'].title()
        )
        return HttpResponse('Survivor created')


class SurvivorLoginByEmailView(View):
    model = User
    template_name = 'userapp/index.html'
    form_class = SurvivorLoginByEmailForm

    # def get(self, request, *args, **kwargs):
    #     return render(self.request, 'userapp/index.html')

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        # return redirect("userapp:survivor-dashboard")
        try:
            user = User.objects.get(email=self.request.POST['loginemail'])
            if user.check_password(self.request.POST['loginpssword']):
                if user.is_survivor:
                    login(self.request, user)
                    # return HttpResponse('Log in successfull')
                    return redirect("userapp:survivor-dashboard")
                else:
                    return JsonResponse({'message': 'Unauthorised access'}, status=400)
            else:
                return JsonResponse({'message': 'Incorrect Password'}, status=400)
        except:
            return JsonResponse({'message': 'User with this email does not exists'}, status=400)

        # return HttpResponse("User Exists")


class SurvivorLoginByMobileNumberView(View):
    model = User
    template_name = 'userapp/index.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/index.html')

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        # return redirect("userapp:survivor-dashboard")
        try:
            user = User.objects.get(phone_number=self.request.POST['loginmobile'])
            if user.check_password(self.request.POST['loginpssword2']):
                if user.is_survivor:
                    login(self.request, user)
                    # return HttpResponse('Log in successfull')
                    return redirect("userapp:survivor-dashboard")
                else:
                    return JsonResponse({'message': 'Unauthorised access'}, status=400)
            else:
                return JsonResponse({'message': 'Incorrect Password'}, status=400)
        except:
            return JsonResponse({'message': 'User with this mobile number does not exists'}, status=400)


class Dashboard(ListView):
    model = Assault
    template_name = 'userapp/record-an-assault.html'

    # login_url = "userapp:home"

    def get(self, request, *args, **kwargs):
        if not self.request.user.is_anonymous:
            objects = Assault.objects.filter(user=self.request.user)
            return render(self.request, 'userapp/record-an-assault.html', {'objects': objects})
        else:
            return render(self.request, 'userapp/record-an-assault.html')


class PaymentView(View):
    template_name = 'userapp/payment.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/payment.html')


class RecordAnAssault(View):
    model = Assault
    template_name = 'userapp/record-fill.html'
    form_class = AssaultForm

    def get(self, request, *args, **kwargs):
        request.session['type_of_violence'] = self.request.GET.get('type_of_violence')
        return render(self.request, 'userapp/record-fill.html')

    # def post(self, request, *args, **kwargs):
    #     print(self.request.POST)
    #     return redirect("/")


class RecordAssault2(View):
    model = AssaultQuestionAnswer
    template_name = 'userapp/assault-form-2.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/assault-form-2.html')

    def post(self, request, *args, **kwargs):
        d = {}
        for key in json.loads(self.request.POST['data']):
            d.update(key)
        return render(self.request, 'userapp/assault-form-2.html')


class AssaultRecordQuestionAnswer(View):
    model = AssaultQuestionAnswer
    template_name = 'userapp/assault-form-2.html'
    form_class = AssaultQuestionAnswerForm

    def post(self, request, *args, **kwargs):
        x = json.loads(self.request.POST['data'])
        y = json.loads(x)
        final_data = {}
        for a in y:
            if a:
                final_data.update(a)
        for y in json.loads(self.request.POST['data2']):
            if y:
                final_data.update(y)
        print(final_data)
        Assault.objects.create(
            user=self.request.user,
            type_of_violence=final_data['type_of_violence'],
            first_name=final_data['first_name'],
            last_name=final_data['last_name'],
            gender=final_data['gender'],
            build=final_data['build'],
            height=final_data['height'],
            eye_color=final_data['eye_color'],
            special_body_mark=final_data['special_body_mark'],
            mobile_number=final_data['mobile_number'],
            hair_color=final_data['hair_color'],
            skin_color=final_data['skin_color'],
            race=final_data['race'],
            year=final_data['year'],
            time=final_data['time'],
            date=final_data['date'],
            anything_else_about_date=final_data['anything_else_about_date'],
            where_it_happened=final_data['where_it_happened'],
            other_info_about_location=final_data['other_info_about_location'],
            anyone_see_hear=final_data['anyone_see_hear'],
            tell_anyone=final_data['tell_anyone'],
            after_before_incident=final_data['after_before_incident'],
            information_about_people_told=final_data['information_about_people_told'],
            info_about_people_described_above=final_data['info_about_people_described_above'],
            offender_told_anyone=final_data['offender_told_anyone'],
            consent_details=final_data['consent_details'],
            what_happened=final_data['what_happened'],
            number_of_offenders=final_data['number_of_offenders'],
            anyone_else_with_offender=final_data['anyone_else_with_offender'],
            name_of_person_with_offender=final_data['name_of_person_with_offender'],
            info_about_person_with_offender=final_data['info_about_person_with_offender'],
            other_info_about_person_with_offender=final_data['other_info_about_person_with_offender'],
            evidence=final_data['evidence'],
            allow_info_match=final_data['allow_info_match']
        )
        return redirect("userapp:survivor-dashboard")


class ServiceProviderView(View):
    model = AssaultQuestionAnswer
    template_name = 'userapp/service-provider.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/service-provider.html')


class MyBookingsView(View):
    model = AssaultQuestionAnswer
    template_name = 'userapp/booking-ongoing.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/booking-ongoing.html')


class FaqView(View):
    model = Faq
    template_name = 'userapp/faq.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/faq.html')


class ContactView(View):
    model = Contact
    template_name = 'userapp/contact-us.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/contact-us.html')


class NotificationDetail(View):
    model = Notification
    template_name = 'userapp/notification-view.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/notification-view.html')


class SurvivorProfileView(View):
    model = Survivor
    template_name = 'userapp/myprofile.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/myprofile.html')


class SurvivorLogout(View):

    def get(self, request, *args, **kwargs):
        logout(self.request)
        return redirect("userapp:home")


class PasswordResetView(View):
    template_name = 'userapp/password_reset.html'

    # def get(self, request, *args, **kwargs):
    #     return render(request, 'password_reset.html')

    def post(self, request, *args, **kwargs):
        user = get_user_model()
        email = request.POST.get('email')
        email_template = "userapp/password_reset_email.html"
        user_qs = user.objects.filter(email=email)
        print(user_qs)
        if len(user_qs) == 0:
            # messages.error(request, 'Email does not exists')
            # return render(request, 'password_reset.html')
            return JsonResponse({'message': 'Email does not exists'}, status=400)

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
            return redirect('userapp:password-reset-done')
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
            return redirect('userapp:password-reset-done')


class PasswordResetConfirmView(View):
    template_name = 'userapp/password_reset_confirm.html'

    def get(self, request, *args, **kwargs):
        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if token_generator.check_token(user_object, token):
            return render(self.request, 'userapp/password_reset_confirm.html')
        else:
            messages.error(self.request, "Link is Invalid")
            return render(self.request, 'userapp/password_reset_confirm.html')

    def post(self, request, *args, **kwargs):
        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if not token_generator.check_token(user_object, token):
            messages.error(self.request, "Link is Invalid")
            return render(request, 'userapp/password_reset_confirm.html')

        password1 = self.request.POST.get('new_password1')
        password2 = self.request.POST.get('new_password2')

        if password1 != password2:
            messages.error(self.request, "Passwords do not match")
            return render(self.request, 'userapp/password_reset_confirm.html')
        elif len(password1) < 8:
            messages.error(
                self.request, "Password must be atleast 8 characters long")
            return render(request, 'userapp/password_reset_confirm.html')
        elif password1.isdigit() or password2.isdigit() or password1.isalpha() or password2.isalpha():
            messages.error(
                self.request, "Passwords must have a mix of numbers and characters")
            return render(request, 'userapp/password_reset_confirm.html')
        else:
            token = kwargs['token']
            user_id_b64 = kwargs['uidb64']
            uid = urlsafe_base64_decode(user_id_b64).decode()
            user_object = user.objects.get(id=uid)
            user_object.set_password(password1)
            user_object.save()
            return redirect('userapp:password-reset-complete')


class ServiceProviderSignup(View):
    model = ServiceProvider

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        data1 = json.loads(self.request.POST['data1'])
        data2 = json.loads(self.request.POST['data2'])
        final_data = {}
        for data in data1:
            final_data.update(data)
        for d in data2:
            final_data.update(d)
        print(final_data)
        try:
            user = User.objects.get(email=final_data['email'])
            if user:
                return JsonResponse({'message': 'User with this email already exists'}, status=400)
        except:
            user = User.objects.create(
                email=final_data['email'],
                phone_number=final_data['mobile_number'],
                first_name=final_data['contact_persons_first_name'],
                last_name=final_data['contact_persons_last_name'],
                is_service_provider=True
            )
            user.set_password(final_data['password'])
            user.save()
            ServiceProvider.objects.create(
                user=user,
                organization=final_data['organization'],
                organization_type=final_data['organization_type'],
                mobile_number=final_data['mobile_number'],
                email=final_data['email'],
                password=final_data['password'],
                company_logo=final_data['company_logo'],
                company_name=final_data['company_name'],
                contact_persons_first_name=final_data['contact_persons_first_name'],
                contact_persons_last_name=final_data['contact_persons_last_name'],
                company_address_1=final_data['company_address_1'],
                company_address_2=final_data['company_address_2'],
                country=final_data['country'],
                city=final_data['city'],
                zip_code=final_data['zip_code']
            )
            return HttpResponse('survivor created')


class ProviderSignIn(View):
    model = User

    def get(self, request, *args, **kwargs):
        try:
            if self.request.COOKIES.get('cid1') and self.request.COOKIES.get('cid2') and self.request.COOKIES.get(
                    'cid3'):
                return render(self.request, 'userapp/index.html',
                              {'p_email': self.request.COOKIES.get('cid1'),
                               'p_password': self.request.COOKIES.get('cid2'),
                               'p_remember_me': self.request.COOKIES.get('cid3')})
            else:
                return render(self.request, 'userapp/index.html')
        except:
            return render(self.request, 'userapp/index.html')

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        incoming_data = json.loads(self.request.POST['data'])
        final_data = {}
        for data in incoming_data:
            final_data.update(data)
        print(final_data)
        print(final_data['email'])
        try:
            user = User.objects.get(email=final_data['email'])
            # remember_me = final_data['check'].title()
            print(user)
            # remember_me = final_data['check']
            # print(remember_me)
            print(user.check_password(final_data['password']))
            if user.check_password(final_data['password']):
                if user.is_service_provider:
                    login(self.request, user)
                    # return HttpResponse('Log in successfull')
                    # if remember_me:
                    #     cookie_age = 60 * 60 * 24
                    #     self.request.session.set_expiry(1209600)
                    #     response = HttpResponse()
                    #     response.set_cookie('cid1', self.request.POST['email'], max_age=cookie_age)
                    #     response.set_cookie('cid2', self.request.POST['password'], max_age=cookie_age)
                    #     response.set_cookie('cid3', self.request.POST['remember_me'], max_age=cookie_age)
                    #     return response
                    # else:
                    #     self.request.session.set_expiry(0)
                    # return redirect('adminpanel:superadmin-dashboard"')
                    return redirect("userapp:provider-requests")
                else:
                    return JsonResponse({'message': 'Unauthorised access'}, status=400)
            else:
                return JsonResponse({'message': 'Incorrect Password'}, status=400)
        except Exception as e:
            print('Exception--', e)
            return JsonResponse({'message': 'User with this email does not exists'}, status=400)


class ServiceProviderRequests(View):
    model = Assault

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/request.html')


class SurvivorFaq(View):
    template_name = 'userapp/provider-faq.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/provider-faq.html')


class SurvivorContact(View):
    template_name = 'userapp/provider-contact.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/provider-contact.html')


class SurvivorNotificationDetail(View):
    template_name = 'userapp/survivor-notification.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/survivor-notification.html')


class SurvivorAvailability(View):
    template_name = 'userapp/availability.html'
    model = ServiceProviderSlots

    def get(self, request, *args, **kwargs):
        user = self.request.user
        try:
            service_provider = ServiceProvider.objects.get(user=user)
            return render(self.request, 'userapp/availability.html',
                          {'object_list': ServiceProviderSlots.objects.filter(user=service_provider)[:15]})
        except Exception as e:
            return render(self.request, 'userapp/availability.html',
                          {'object_list': ''})


class SurvivorSubscriptionView(View):
    template_name = 'userapp/subscription.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/subscription.html')


class ProviderForgotPassword(View):
    template_name = 'userapp/index.html'

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        # print(request.data)
        incoming_data = json.loads(self.request.POST['data'])

        f_d = {}
        for d in incoming_data:
            f_d.update(d)
        print(f_d)
        user = get_user_model()
        email = f_d['email']
        print(email)
        email_template = "userapp/provider_password_reset_email.html"
        user_qs = user.objects.filter(email=email)
        print(user_qs)
        if len(user_qs) == 0:
            # messages.error(request, 'Email does not exists')
            # return render(request, 'password_reset.html')
            return JsonResponse({'message': 'Email does not exists'}, status=400)

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
            return redirect('userapp:password-reset-done')
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
            return redirect('userapp:password-reset-done')


class ProviderPasswordResetConfirmView(View):
    template_name = 'userapp/password_reset_confirm.html'

    def get(self, request, *args, **kwargs):
        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if token_generator.check_token(user_object, token):
            return render(self.request, 'userapp/password_reset_confirm.html')
        else:
            messages.error(self.request, "Link is Invalid")
            return render(self.request, 'userapp/password_reset_confirm.html')

    def post(self, request, *args, **kwargs):
        token = kwargs['token']
        user_id_b64 = kwargs['uidb64']
        uid = urlsafe_base64_decode(user_id_b64).decode()
        user_object = user.objects.get(id=uid)
        token_generator = default_token_generator
        if not token_generator.check_token(user_object, token):
            messages.error(self.request, "Link is Invalid")
            return render(request, 'userapp/password_reset_confirm.html')

        password1 = self.request.POST.get('new_password1')
        password2 = self.request.POST.get('new_password2')

        if password1 != password2:
            messages.error(self.request, "Passwords do not match")
            return render(self.request, 'userapp/password_reset_confirm.html')
        elif len(password1) < 8:
            messages.error(
                self.request, "Password must be atleast 8 characters long")
            return render(request, 'userapp/password_reset_confirm.html')
        elif password1.isdigit() or password2.isdigit() or password1.isalpha() or password2.isalpha():
            messages.error(
                self.request, "Passwords must have a mix of numbers and characters")
            return render(request, 'userapp/password_reset_confirm.html')
        else:
            token = kwargs['token']
            user_id_b64 = kwargs['uidb64']
            uid = urlsafe_base64_decode(user_id_b64).decode()
            user_object = user.objects.get(id=uid)
            user_object.set_password(password1)
            user_object.save()
            return redirect('userapp:password-reset-complete')


class CreateSlotView(View):
    model = ServiceProviderSlots

    def post(self, request, *args, **kwargs):
        print('Form single slot creation', self.request.POST)
        user = self.request.user
        service_provider = ServiceProvider.objects.get(user=user)
        date_time_str = self.request.POST['selected_date'].split(' ')
        month_name = date_time_str[1]
        datetime_object = datetime.strptime(month_name, "%B").month
        if datetime_object < 10:
            datetime_object = '0' + str(datetime_object)
        else:
            datetime_object = datetime_object
        d = date_time_str[0]
        if int(d) < 10:
            d = '0' + str(d)
        else:
            d = d
        selected_date_obj = d + '/' + str(datetime_object) + '/' + date_time_str[2]
        date_time_obj = datetime.strptime(selected_date_obj, '%d/%m/%Y')
        i = self.request.POST['fee']
        # fee = float(i)
        fee = Decimal(i)
        ServiceProviderSlots.objects.create(
            user=service_provider,
            slot_date=date_time_obj,
            slot_time=self.request.POST['selected_slot'],
            select_slot_type=self.request.POST['select_slot_type'],
            category=self.request.POST['category_type'],
            title=self.request.POST['title'],
            hourly_fees=fee
        )
        return redirect("userapp:provider-availability")


class CreateMultiSlotView(View):
    model = ServiceProviderSlots

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        d = self.request.POST['selected_date'].split(",")
        e = self.request.POST['selected_slot'].split(",")
        f = self.request.POST['select_slot_type'].split(",")
        g = self.request.POST['category_type'].split(",")
        h = self.request.POST['multi_title'].split(",")
        i = self.request.POST['multi_fee'].split(",")
        data = zip(d, e, f, g, h, i)
        user = self.request.user
        service_provider = ServiceProvider.objects.get(user=user)
        # print(list(data))
        for x in list(data):
            print('inside for loop', x)
            date_time_str = x[0].split(' ')
            month_name = date_time_str[1]
            datetime_object = datetime.strptime(month_name, "%B").month
            if datetime_object < 10:
                datetime_object = '0' + str(datetime_object)
            else:
                datetime_object = datetime_object
            d = date_time_str[0]
            if int(d) < 10:
                d = '0' + str(d)
            else:
                d = d
            selected_date_obj = d + '/' + str(datetime_object) + '/' + date_time_str[2]
            date_time_obj = datetime.strptime(selected_date_obj, '%d/%m/%Y')
            i = x[5]
            fee = Decimal(i)
            ServiceProviderSlots.objects.create(
                user=service_provider,
                slot_date=date_time_obj,
                slot_time=x[1],
                select_slot_type=x[2],
                # category=self.request.POST['category_type']
                category=x[3],
                title=x[4],
                hourly_fees=fee,
            )
        return redirect("userapp:provider-availability")
