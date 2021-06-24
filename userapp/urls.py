from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import PasswordResetDoneView, PasswordResetCompleteView
from .views import HomeView, SurvivorSignUp, Dashboard, RecordAnAssault, RecordAssault2, AssaultRecordQuestionAnswer, \
    ServiceProviderView, MyBookingsView, FaqView, ContactView, NotificationDetail, SurvivorProfileView, \
    SurvivorLoginByEmailView, CompleteSurvivorSignUp, SurvivorLogout, SurvivorLoginByMobileNumberView, \
    PasswordResetView, PasswordResetConfirmView, ServiceProviderSignup, ProviderSignIn, ServiceProviderRequests, \
    SurvivorFaq, SurvivorContact, SurvivorNotificationDetail, SurvivorAvailability, SurvivorSubscriptionView, \
    ProviderForgotPassword, ProviderPasswordResetConfirmView, CreateSlotView, GuestAssaultUser, \
    GuestAssaultUserForm2View, CreateMultiSlotView, PaymentView

app_name = 'userapp'

urlpatterns = [
    path('', HomeView.as_view(), name='home'),
    path('survivor-signup/', SurvivorSignUp.as_view(), name='survivor-signup'),
    path('complete-survivor-signup/', CompleteSurvivorSignUp.as_view(), name='complete-survivor-signup'),
    path('survivor-login-by-email/', SurvivorLoginByEmailView.as_view(), name='survivor-login-by-email'),
    path('survivor-login-by-mobile/', SurvivorLoginByMobileNumberView.as_view(), name='survivor-login-by-mobile'),
    path("password-reset/", PasswordResetView.as_view(), name="password-reset"),
    path("provider-password-reset/", ProviderForgotPassword.as_view(), name="provider-password-reset"),
    path("password-reset-done/", PasswordResetDoneView.as_view(template_name='userapp/password_reset_done.html'),
         name="password-reset-done"),
    path("password-reset-confirm/<uidb64>/<token>/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("provider-password-reset-confirm/<uidb64>/<token>/", ProviderPasswordResetConfirmView.as_view(), name="provider-password-reset-confirm"),
    path("password-reset-done/", PasswordResetDoneView.as_view(template_name='userapp/password_reset_done.html'),
         name="password-reset-done"),
    path("password-reset-complete/",
         PasswordResetCompleteView.as_view(template_name='userapp/password_reset_complete.html'),
         name="password-reset-complete"),
    path('survivor-dashboard/', Dashboard.as_view(), name='survivor-dashboard'),
    path('record-assault/', RecordAnAssault.as_view(), name='record-assault'),
    path('record-assault-2/', RecordAssault2.as_view(), name='record-assault-2'),
    path('record-assault-qa/', AssaultRecordQuestionAnswer.as_view(), name='record-assault-qa'),
    path('service-provider/', ServiceProviderView.as_view(), name='service-provider'),
    path('ongoing-booking/', MyBookingsView.as_view(), name='ongoing-booking'),
    path('faq/', FaqView.as_view(), name='faq'),
    path('survivor-faq/', SurvivorFaq.as_view(), name='survivor-faq'),
    path('contact-us/', ContactView.as_view(), name='contact-us'),
    path('survivor-contact/', SurvivorContact.as_view(), name='survivor-contact'),
    path('notification-detail/', NotificationDetail.as_view(), name='notification-detail'),
    path('survivor-profile/', SurvivorProfileView.as_view(), name='survivor-profile'),
    path('survivor-logout/', SurvivorLogout.as_view(), name='survivor-logout'),
    path('service-provider-signup/', ServiceProviderSignup.as_view(), name='service-provider-signup'),
    path('provider-signin/', ProviderSignIn.as_view(), name='provider-signin'),
    path('provider-requests/', ServiceProviderRequests.as_view(), name='provider-requests'),
    path('survivor-notification-detail/', SurvivorNotificationDetail.as_view(), name='survivor-notification-detail'),
    path('provider-availability/', SurvivorAvailability.as_view(), name='provider-availability'),
    path('survivor-subscription/', SurvivorSubscriptionView.as_view(), name='survivor-subscription'),
    path('create-slot/', CreateSlotView.as_view(), name='create-slot'),
    path('create-multi-slot/', CreateMultiSlotView.as_view(), name='create-multi-slot'),
    path('guest-assault/', GuestAssaultUser.as_view(), name='guest-assault'),
    path('guest-assault-2/', GuestAssaultUserForm2View.as_view(), name='guest-assault-2'),
    path('payment/', PaymentView.as_view(), name='payment'),
]+ static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
