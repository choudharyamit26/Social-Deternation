import json
from datetime import datetime
from decimal import Decimal
from random import randint

from adminpanel.views import User
from adminpanel.models import Otp
from django.conf.global_settings import DEFAULT_FROM_EMAIL
from django.contrib import messages
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import render, HttpResponse, redirect
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views.generic import View, ListView, CreateView
import datetime
import pytz

import telnyx

utc = pytz.UTC
from .forms import SurvivorSignUpForm, AssaultForm, AssaultQuestionAnswerForm, SurvivorLoginByEmailForm
from .models import Survivor, Assault, AssaultQuestionAnswer, Faq, Contact, Notification, ServiceProvider, \
    ServiceProviderSlots
from adminpanel.utils import send_otp

telnyx.api_key = "KEY0179F531AF3BB551376A921623235245_E9m3eGUsHbns1W0Juxoi24"

user = get_user_model()


class HomeView(View):
    template_name = 'userapp/index.html'

    def get(self, request, *args, **kwargs):
        print(request.META.get("REMOTE_ADDR"))
        print(self.request.META.get("REMOTE_ADDR"))
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
        print(self.request.POST)
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
                {'message': 'This phone number is already in use. Please supply a different phone number.'},
                status=400)
        else:
            try:
                send_otp(+91, self.request.POST['mobile_number'])
                return HttpResponse('Survivor created')
            except Exception as e:
                return JsonResponse({'message': 'Something went wrong'}, status=400)


class CompleteSurvivorSignUp(View):
    model = User
    template_name = 'userapp/index.html'

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        if self.request.POST['nick_name'] == '' or self.request.POST['first_name'] == '' or self.request.POST[
            'last_name'] == '':
            return JsonResponse({'message': 'One or more fields are empty'}, status=400)
        try:
            if self.request.POST['avi'] != '' or self.request.POST['avi'] != None:
                user = User.objects.get(avi=self.request.POST['avi'])
                print(user)
                return JsonResponse(
                    {'message': 'User with this screen name already exists. Please supply different screen name'},
                    status=400)
        except Exception as e:
            print(e)
            user = User.objects.create(
                email=self.request.POST['email'],
                phone_number=self.request.POST['mobile_number'],
                first_name=self.request.POST['first_name'],
                last_name=self.request.POST['last_name'],
                nick_name=self.request.POST['nick_name'],
                avi=self.request.POST['avi'],
                is_survivor=True
            )
            user.set_password(self.request.POST['password'])
            user.save()
            survivor = Survivor.objects.create(
                user=user,
                client_code=self.request.POST['client_code'],
                mobile_number=self.request.POST['mobile_number'],
                consent=self.request.POST['check'].title(),

            )
            return JsonResponse(
                {'message': 'Survivor created'},
                status=200)


class SurvivorLoginByEmailView(View):
    model = User
    template_name = 'userapp/index.html'
    form_class = SurvivorLoginByEmailForm

    # def get(self, request, *args, **kwargs):
    #     return render(self.request, 'userapp/index.html')

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
        email_template = "userapp/otp_email.html"
        # return redirect("userapp:survivor-dashboard")
        if self.request.POST.get('loginemail') == '':
            return JsonResponse({'message': 'Please enter a valid email'}, status=400)
        if self.request.POST.get('loginpssword') == '':
            return JsonResponse({'message': 'Please enter a valid password'}, status=400)

        try:
            user = User.objects.get(email=self.request.POST['loginemail'])
            print(user.check_password(self.request.POST['loginpssword']))
            if user.check_password(self.request.POST['loginpssword']):
                if user.is_survivor:
                    login(self.request, user)
                    # return HttpResponse('Log in successfull')
                    email = user.email
                    otp = randint(100000, 999999)
                    print(otp)
                    Otp.objects.create(email=email, otp=otp)
                    user = user
                    site_name = "Brasi"
                    context = {
                        "email": email,
                        "user": user,
                        "otp": otp,
                        "site_name": site_name
                    }
                    subject = "One Time Password"
                    email_body = render_to_string(email_template, context)
                    send_mail(subject, email_body, DEFAULT_FROM_EMAIL,
                              [email], fail_silently=False)
                    # return redirect("userapp:survivor-dashboard")
                    return JsonResponse({'email': email}, status=200)
                else:
                    return JsonResponse({'message': 'Unauthorised access'}, status=400)
            else:
                return JsonResponse({'message': 'Incorrect Password'}, status=400)
        except Exception as e:
            print(e)
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
                    # send_otp(user.country_code, user.phone_number)
                    otp = randint(100000, 999999)
                    Otp.objects.create(number=user.phone_number, otp=otp)
                    telnyx.Message.create(
                        from_="+15736058855",  # Your Telnyx number
                        to='+' + str(int(user.country_code)) + str(user.phone_number),
                        text=f'Your one time password from BRASI is {otp}. This otp is valid for next 60 seconds.'
                    )
                    return JsonResponse({'number': user.phone_number}, status=200)
                    # return redirect("userapp:survivor-dashboard")
                else:
                    return JsonResponse({'message': 'Unauthorised access'}, status=400)
            else:
                return JsonResponse({'message': 'Incorrect Password'}, status=400)
        except Exception as e:
            print(e)
            return JsonResponse({'message': 'User with this mobile number does not exists'}, status=400)


class Dashboard(ListView):
    model = Assault
    template_name = 'userapp/record-an-assault.html'

    # login_url = "userapp:home"

    def get(self, request, *args, **kwargs):
        if not self.request.user.is_anonymous:
            objects = Assault.objects.filter(user=self.request.user)
            return render(self.request, 'userapp/record-an-assault.html',
                          {'objects': objects, 'count': objects.count()})
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
        print('>>>>>', self.request.POST)
        d = {}
        for key in json.loads(self.request.POST['data']):
            d.update(key)
        return render(self.request, 'userapp/assault-form-2.html')


class AssaultRecordQuestionAnswer(LoginRequiredMixin, View):
    model = AssaultQuestionAnswer
    template_name = 'userapp/assault-form-2.html'
    form_class = AssaultQuestionAnswerForm

    # login_url = ''

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/assault-form-2.html')

    def post(self, request, *args, **kwargs):
        print(self.request.POST)
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
        assault_form_obj = Assault.objects.create(
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
        if final_data['allow_info_match']:
            assault_obj = Assault.objects.filter(
                Q(type_of_violence=final_data['type_of_violence'].lower()) |
                Q(first_name=final_data['first_name'].lower()) |
                Q(last_name=final_data['last_name'].lower()) |
                Q(gender=final_data['gender'].lower()) |
                Q(build=final_data['build'].lower()) |
                Q(height=final_data['height'].lower()) |
                Q(eye_color=final_data['eye_color'].lower()) |
                Q(special_body_mark=final_data['special_body_mark'].lower()) |
                Q(mobile_number=final_data['mobile_number']) |
                Q(hair_color=final_data['hair_color'].lower()) |
                Q(skin_color=final_data['skin_color'].lower()) |
                Q(race=final_data['race'].lower()) |
                Q(year=final_data['year']) |
                Q(time=final_data['time']) |
                Q(date=final_data['date']) |
                Q(anything_else_about_date=final_data['anything_else_about_date'].lower()) |
                Q(where_it_happened=final_data['where_it_happened'].lower()) |
                Q(other_info_about_location=final_data['other_info_about_location'].lower()) |
                Q(anyone_see_hear=final_data['anyone_see_hear'].lower()) |
                Q(tell_anyone=final_data['tell_anyone'].lower()) |
                Q(after_before_incident=final_data['after_before_incident'].lower()) |
                Q(information_about_people_told=final_data['information_about_people_told'].lower()) |
                Q(info_about_people_described_above=final_data['info_about_people_described_above'].lower()) |
                Q(offender_told_anyone=final_data['offender_told_anyone'].lower()) |
                Q(consent_details=final_data['consent_details'].lower()) |
                Q(what_happened=final_data['what_happened'].lower()) |
                Q(number_of_offenders=final_data['number_of_offenders']) |
                Q(anyone_else_with_offender=final_data['anyone_else_with_offender'].lower()) |
                Q(name_of_person_with_offender=final_data['name_of_person_with_offender'].lower()) |
                Q(info_about_person_with_offender=final_data['info_about_person_with_offender'].lower()) |
                Q(other_info_about_person_with_offender=final_data['other_info_about_person_with_offender'].lower()) |
                Q(evidence=final_data['evidence'].lower()))
            print('Assault OBJ-->>', assault_obj)
            matched_users = []
            for obj in assault_obj:
                matched_fields_count = 0
                if obj.type_of_violence.lower() == final_data['type_of_violence'].lower():
                    matched_fields_count += 1
                if obj.first_name.lower() == final_data['first_name'].lower():
                    matched_fields_count += 1
                if obj.last_name.lower() == final_data['last_name'].lower():
                    matched_fields_count += 1
                if obj.gender.lower() == final_data['gender'].lower():
                    matched_fields_count += 1
                if obj.build.lower() == final_data['build'].lower():
                    matched_fields_count += 1
                if obj.height.lower() == final_data['height'].lower():
                    matched_fields_count += 1
                if obj.eye_color.lower() == final_data['eye_color'].lower():
                    matched_fields_count += 1
                if obj.special_body_mark.lower() == final_data['special_body_mark'].lower():
                    matched_fields_count += 1
                if obj.mobile_number == final_data['mobile_number']:
                    matched_fields_count += 1
                if obj.hair_color.lower() == final_data['hair_color'].lower():
                    matched_fields_count += 1
                if obj.skin_color.lower() == final_data['skin_color'].lower():
                    matched_fields_count += 1
                if obj.race.lower() == final_data['race'].lower():
                    matched_fields_count += 1
                if obj.year == final_data['year']:
                    matched_fields_count += 1
                if obj.time == final_data['time']:
                    matched_fields_count += 1
                if obj.date == final_data['date']:
                    matched_fields_count += 1
                if obj.anything_else_about_date.lower() == final_data['anything_else_about_date'].lower():
                    matched_fields_count += 1
                if obj.where_it_happened.lower() == final_data['where_it_happened'].lower():
                    matched_fields_count += 1
                if obj.other_info_about_location.lower() == final_data['other_info_about_location'].lower():
                    matched_fields_count += 1
                if obj.anyone_see_hear.lower() == final_data['anyone_see_hear'].lower():
                    matched_fields_count += 1
                if obj.tell_anyone.lower() == final_data['tell_anyone'].lower():
                    matched_fields_count += 1
                if obj.after_before_incident.lower() == final_data['after_before_incident'].lower():
                    matched_fields_count += 1
                if obj.information_about_people_told.lower() == final_data['information_about_people_told'].lower():
                    matched_fields_count += 1
                if obj.info_about_people_described_above.lower() == final_data[
                    'info_about_people_described_above'].lower():
                    matched_fields_count += 1
                if obj.offender_told_anyone.lower() == final_data['offender_told_anyone'].lower():
                    matched_fields_count += 1
                if obj.what_happened.lower() == final_data['what_happened'].lower():
                    matched_fields_count += 1
                if obj.number_of_offenders == final_data['number_of_offenders']:
                    matched_fields_count += 1
                if obj.info_about_person_with_offender.lower() == final_data[
                    'info_about_person_with_offender'].lower():
                    matched_fields_count += 1
                if obj.other_info_about_person_with_offender.lower() == final_data[
                    'other_info_about_person_with_offender'].lower():
                    matched_fields_count += 1
                if obj.evidence.lower() == final_data['evidence'].lower():
                    matched_fields_count += 1
                if matched_fields_count >= 14:
                    matched_users.append(obj.first_name)
                print('>>>', matched_fields_count)
            return JsonResponse(
                {'matched_users': matched_users, 'count_of_matched_users': len(matched_users),
                 'name': self.request.user.first_name, 'incident_description': final_data['what_happened'],
                 'skin_color': final_data['skin_color'], 'happened_on': final_data['date'],
                 'allow_info_match': final_data['allow_info_match'], 'id': assault_form_obj.id},
                status=200)
        else:
            # return render(self.request, 'userapp/record-an-assault.html',
            #               {'my_assaults_forms': Assault.objects.filter(user=self.request.user)})
            return redirect("userapp:survivor-dashboard")


class UpdateAssaultForm(LoginRequiredMixin, View):
    model = Assault

    def get(self, request, *args, **kwargs):
        id = self.request.GET.get('id')
        type_of_assistance = self.request.GET.get('help_type')
        try:
            assault_form_obj = Assault.objects.get(id=id)
            assault_form_obj.sought_further_assistance = True
            assault_form_obj.type_of_assistance = type_of_assistance
            assault_form_obj.save()
            return JsonResponse({'message': 'Form updated successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'message': 'Something went wrong'}, status=400)


class ServiceProviderView(View):
    model = AssaultQuestionAnswer
    template_name = 'userapp/service-provider.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/service-provider.html', {'object_list': ServiceProvider.objects.all()})


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


class ServiceProviderProfile(View):
    model = ServiceProvider
    template_name = 'userapp/service-provider-profile.html'

    def get(self, request, *args, **kwargs):
        return render(self.request, 'userapp/service-provider-profile.html')


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
        if email == '':
            return JsonResponse({'message': 'Please enter a valid email'}, status=400)
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
        organization_type = None
        if final_data.get('organization_type'):
            organization_type = final_data.get('organization_type')
        else:
            organization_type = ''

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
                organization_type=organization_type,
                mobile_number=final_data['mobile_number'],
                email=final_data['email'],
                password=final_data['password'],
                company_logo=final_data.get('company_logo'),
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
        if not final_data.get('membership_code') or final_data['membership_code'] == '':
            return JsonResponse({'message': 'Membership code cannot be blank'}, status=400)
        if final_data['email'] == '':
            return JsonResponse({'message': 'Email cannot be blank'}, status=400)
        if final_data['password'] == '':
            return JsonResponse({'message': 'Password cannot be blank'}, status=400)
        if final_data['membership_code'] == '':
            return JsonResponse({'message': 'Membership code cannot be blank'}, status=400)

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
                    # return redirect("userapp:provider-requests")
                    send_otp(user.country_code, user.phone_number)
                    return JsonResponse({'number': user.phone_number}, status=200)
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
                          {'object_list': ServiceProviderSlots.objects.filter(user=service_provider)})
        except Exception as e:
            return render(self.request, 'userapp/availability.html',
                          {'object_list': ''})


class SurvivorCalendarEvent(View):

    def get(self, request, *args, **kwargs):
        print(self.request.GET)
        # return JsonResponse({'data':'clicked event'})
        service_provider = ServiceProvider.objects.get(user=self.request.user)
        service_provider_slots = ServiceProviderSlots.objects.filter(user=service_provider,
                                                                     slot_date=self.request.GET['date'])
        print(service_provider_slots)
        return render(self.request, 'userapp/calendar-event.html',
                      {'object_list': ServiceProviderSlots.objects.filter(user=service_provider),
                       'slots_per_day': service_provider_slots})


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
        if f_d['membership_code'] == '':
            return JsonResponse({'message': 'Membership code may not be blank'}, status=400)
        if f_d['email'] == '':
            return JsonResponse({'message': 'Email may not be blank'}, status=400)
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
        print()
        selected_slot = self.request.POST['selected_slot'].split(',')
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
        i = self.request.POST.get('fee')
        # fee = float(i)
        try:
            fee = Decimal(i)
        except:
            fee = 0
        for i in range(len(self.request.POST['selected_slot'].split(','))):
            ServiceProviderSlots.objects.create(
                user=service_provider,
                slot_date=date_time_obj,
                slot_time=selected_slot[i],
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
        e = self.request.POST['selected_slot']
        e = json.dumps(e)
        selected_slot_list = []
        for x in json.loads(e).split('}'):
            if x.startswith('{'):
                selected_slot_list.append(x.replace('{', '', 1))
            elif x.startswith(',{'):
                selected_slot_list.append(x.replace(',{', '', 1))
        slots = []
        for i in selected_slot_list:
            slots.append({i.split(',')[1].split(':"')[1].replace('" ', '', 1).replace('"', '', 1):
                              i.split(',')[0].split(':"')[1].replace('"', '', 1)})

        slots_dict = {}
        for slot in slots:
            for key in slot.keys():
                if key in slots_dict:
                    slots_dict[key].append(slot[key])
                else:
                    slots_dict[key] = [slot[key]]
            # print(key,value)
        f = self.request.POST['select_slot_type'].split(",")
        g = self.request.POST['category_type'].split(",")
        h = self.request.POST['multi_title'].split(",")
        fee_list = self.request.POST['multi_fee'].split(",")
        new_fee_list = ['0'] * len(f)
        for i in range(len(f)):
            if f[i] == 'Volunteer':
                pass
            else:
                new_fee_list[i] = 'p'
        counter = 0
        for i in range(len(new_fee_list)):
            if new_fee_list[i] == 'p':
                new_fee_list[i] = fee_list[counter]
                counter += 1
        if len(d) == len(h) and len(d) == len(f) and len(d) == len(g):
            data = zip(d, f, g, h, new_fee_list)
            user = self.request.user
            service_provider = ServiceProvider.objects.get(user=user)
            for x in list(data):
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
                try:
                    i = x[4]
                    fee = Decimal(i)
                except:
                    fee = 0
                for i in slots_dict[x[0]]:
                    slot_obj = ServiceProviderSlots.objects.create(
                        user=service_provider,
                        slot_date=date_time_obj,
                        slot_time=i,
                        select_slot_type=x[1],
                        # category=self.request.POST['category_type']
                        category=x[2],
                        title=x[3],
                        hourly_fees=fee,
                    )
            return redirect("userapp:provider-availability")
        else:
            return JsonResponse({'data': 'error'}, status=400)


class GetServiceProviderAvailability(LoginRequiredMixin, View):
    model = ServiceProviderSlots

    def get(self, request, *args, **kwargs):
        print(self.request.GET)
        service_provider = ServiceProvider.objects.get(id=self.request.GET.get('id'))
        try:
            service_provider_slots = ServiceProviderSlots.objects.filter(user=service_provider)
            data = {'name': service_provider_slots[0].user.contact_persons_first_name + ' ' + service_provider_slots[
                0].user.contact_persons_last_name}
            slots = {}
            for obj in service_provider_slots:
                if f'{obj.slot_date}' in data:
                    data[f'{obj.slot_date}'].append(obj.slot_time)
                else:
                    data[f'{obj.slot_date}'] = [obj.slot_time]
            print(data)
            # data = data.update(slots)
            # print(data)
            return JsonResponse({'data': data}, status=200)
        except:
            data = {
                'name': service_provider.contact_persons_first_name + ' ' + service_provider.contact_persons_last_name}
            return JsonResponse({'message': 'No slots available', 'data': data}, status=400)


class SendOtp(View):
    model = Otp

    def get(self, request, *args, **kwargs):
        number = self.request.GET.get('number')
        try:
            send_otp(+91, number)
            return JsonResponse({'message': 'Otp Sent successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'message': 'Something went wrong'}, status=400)


class VerifyOtp(View):
    model = Otp

    def get(self, request, *args, **kwargs):
        otp = self.request.GET.get('otp')
        try:
            otp_obj = Otp.objects.filter(otp=int(otp)).first()
            if int(otp) == otp_obj.otp and datetime.datetime.now() > otp_obj.created_at.replace(
                    tzinfo=None) + datetime.timedelta(
                seconds=60):
                return JsonResponse({'message': 'Otp has expired'}, status=400)
            elif int(otp) == otp_obj.otp:
                otp_obj = Otp.objects.filter(otp=int(otp))
                for i in otp_obj:
                    i.delete()
                return JsonResponse({'message': 'Otp verified successfully'}, status=200)
            else:
                return JsonResponse({'message': 'Incorrect otp'}, status=400)
        except Exception as e:
            print(e)
            return JsonResponse({'message': 'Invalid otp'}, status=400)


class ResendOtp(View):
    model = Otp

    def get(self, request, *args, **kwargs):
        number = self.request.GET.get('number')
        try:
            user_obj = User.objects.get(phone_number=number)
            send_otp(user_obj.country_code, number)
            return JsonResponse({'message': 'Otp sent successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'message': str(e)}, status=400)


class SurvivorResendOtp(View):
    model = Otp

    def get(self, request, *args, **kwargs):
        email = self.request.GET.get('email')
        email_template = "userapp/otp_email.html"
        try:
            user_obj = User.objects.get(email=email)
            # send_otp(user_obj.country_code, number)
            otp = randint(100000, 999999)
            print(otp)
            Otp.objects.create(email=email, otp=otp)
            user = user_obj
            site_name = "Brasi"
            context = {
                "email": email,
                "user": user,
                "otp": otp,
                "site_name": site_name
            }
            subject = "One Time Password"
            email_body = render_to_string(email_template, context)
            send_mail(subject, email_body, DEFAULT_FROM_EMAIL,
                      [email], fail_silently=False)

            return JsonResponse({'message': 'Otp sent successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'message': str(e)}, status=400)


class ProviderResendOtp(View):
    model = Otp

    def get(self, request, *args, **kwargs):
        number = self.request.GET.get('number')
        try:
            send_otp(+91, number)
            return JsonResponse({'message': 'Otp Sent successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'message': 'Something went wrong'}, status=400)
