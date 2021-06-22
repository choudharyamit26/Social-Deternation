from django.urls import path
from django.contrib.auth.views import LogoutView, PasswordResetDoneView, PasswordResetCompleteView
from .views import LoginView, Dashboard, SubscriptionView, SurvivorsView, CardInformationView, MyProfileView, \
    PasswordResetView, PasswordResetConfirmView, SuperAdminLogin, SuperAdminDashboard, CustomerManagementView, \
    SuperAdminLogout, PasswordChangeView, PasswordChangeDoneView, SuperAdminBrasiSupscriptionView, \
    SuperAdminClientsView, \
    SuperAdminServiceProviders, SuperAdminProvidersCategory, SuperAdminAssaultFormView, SuperAdminAssaultRecords, \
    CreateOrganization, CreateSubscriptionPlan, EditOrganization, DeleteOrganization, ExportOrganizationDataView, \
    ExportSubscriptionPlanDataView, InactiveOrganization, InactiveSubscriptionPlan, EditSubscriptionPlan, \
    DeleteSubscriptionPlan, SubscriptionDetailView, HeroView, SuperAdminGeneralSupscriptionView, \
    InactiveSubscriptionPlan2, DeleteGeneralSubscriptionPlan, EditGeneralSubscriptionPlan, \
    CreateGeneralSubscriptionPlan, CMSBenefits, CMSFeature, CMSHowItWorks, CMSSocialPages, CMSPrivacyPolicy, \
    CMSTermsOfUse, FaqSurvivors, FaqService, FaqLicense, ReportSurvivor, ReportServiceProvider, VoucherView, \
    SpecialUserView, MailBoxView, SuperAdminNotifications

app_name = 'adminpanel'

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("superadmin/", SuperAdminLogin.as_view(), name="superadmin"),
    path("logout/", LogoutView.as_view(template_name='logout.html'), name="logout"),
    path("super-admin-logout/", SuperAdminLogout.as_view(), name="super-admin-logout"),
    path("customer-management/", CustomerManagementView.as_view(), name="customer-management"),
    path("dashboard/", Dashboard.as_view(), name="dashboard"),
    path("superadmin-dashboard/", SuperAdminDashboard.as_view(), name="superadmin-dashboard"),
    path("subscription/", SubscriptionView.as_view(), name="subscription"),
    path("survivors/", SurvivorsView.as_view(), name="survivors"),
    path("card-information/", CardInformationView.as_view(), name="card-information"),
    path("my-profile/", MyProfileView.as_view(), name="my-profile"),
    path("superadmin-subscription-plan/", SuperAdminBrasiSupscriptionView.as_view(),
         name="superadmin-subscription-plan"),
    path("superadmin-general-subscription-plan/", SuperAdminGeneralSupscriptionView.as_view(),
         name="superadmin-general-subscription-plan"),
    path("superadmin-clients/", SuperAdminClientsView.as_view(), name="superadmin-clients"),
    path("superadmin-service-providers/", SuperAdminServiceProviders.as_view(), name="superadmin-service-providers"),
    path("superadmin-assault-form/", SuperAdminAssaultFormView.as_view(), name="superadmin-assault-form"),
    path("superadmin-assault-records/", SuperAdminAssaultRecords.as_view(), name="superadmin-assault-records"),
    path("create-organization/", CreateOrganization.as_view(), name="create-organization"),
    path("superadmin-service-providers-category/", SuperAdminProvidersCategory.as_view(),
         name="superadmin-service-providers-category"),
    path("password-reset/", PasswordResetView.as_view(), name="password-reset"),
    path("password-reset-confirm/<uidb64>/<token>/", PasswordResetConfirmView.as_view(),
         name="password-reset-confirm"),
    path("password-reset-done/", PasswordResetDoneView.as_view(template_name='password_reset_done.html'),
         name="password-reset-done"),
    path("password-reset-complete/", PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'),
         name="password-reset-complete"),
    path('change-password/', PasswordChangeView.as_view(template_name='superadmin/change_password.html'),
         name='change_password'),
    path('password-change-done/',
         PasswordChangeDoneView.as_view(template_name='superadmin/change_password_done.html'),
         name='password_change_done'),
    path('create-subscription-plan/', CreateSubscriptionPlan.as_view(), name='create-subscription-plan'),
    path('create-general-subscription-plan/', CreateGeneralSubscriptionPlan.as_view(),
         name='create-general-subscription-plan'),
    path('edit-subscription-plan/', EditSubscriptionPlan.as_view(), name='edit-subscription-plan'),
    path('edit-general-subscription-plan/', EditGeneralSubscriptionPlan.as_view(),
         name='edit-general-subscription-plan'),
    path('edit-organization/', EditOrganization.as_view(), name='edit-organization'),
    path('delete-organization/<int:pk>/', DeleteOrganization.as_view(), name='delete-organization'),
    path('delete-subscription-plan/<int:pk>/', DeleteSubscriptionPlan.as_view(), name='delete-subscription-plan'),
    path('delete-general-subscription-plan/<int:pk>/', DeleteGeneralSubscriptionPlan.as_view(),
         name='delete-general-subscription-plan'),
    path('inactive-organization/<int:pk>/', InactiveOrganization.as_view(), name='inactive-organization'),
    path('inactive-subscription-plan/<int:pk>/', InactiveSubscriptionPlan.as_view(), name='inactive-subscription-plan'),
    path('inactive-general-subscription-plan/<int:pk>/', InactiveSubscriptionPlan2.as_view(),
         name='inactive-general-subscription-plan'),
    path('subscription-detail/', SubscriptionDetailView.as_view(), name='subscription-detail'),
    path('export-organization-data/', ExportOrganizationDataView.as_view(), name='export-organization-data'),
    path('export-subscription-data/', ExportSubscriptionPlanDataView.as_view(), name='export-subscription-data'),
    path('hero/', HeroView.as_view(), name='hero'),
    path('cms-benefits/', CMSBenefits.as_view(), name='cms-benefits'),
    path('cms-features/', CMSFeature.as_view(), name='cms-features'),
    path('cms-how-it-works/', CMSHowItWorks.as_view(), name='cms-how-it-works'),
    path('cms-social-pages/', CMSSocialPages.as_view(), name='cms-social-pages'),
    path('cms-privacy-policy/', CMSPrivacyPolicy.as_view(), name='cms-privacy-policy'),
    path('cms-terms-of-use/', CMSTermsOfUse.as_view(), name='cms-terms-of-use'),
    path('faq-survivor/', FaqSurvivors.as_view(), name='faq-survivor'),
    path('faq-service/', FaqService.as_view(), name='faq-service'),
    path('faq-license/', FaqLicense.as_view(), name='faq-license'),
    path('report-survivor/', ReportSurvivor.as_view(), name='report-survivor'),
    path('report-service-provider/', ReportServiceProvider.as_view(), name='report-service-provider'),
    path('voucher-view/', VoucherView.as_view(), name='voucher-view'),
    path('user-view/', SpecialUserView.as_view(), name='user-view'),
    path('mail-box/', MailBoxView.as_view(), name='mail-box'),
    path('superadmin-notification/', SuperAdminNotifications.as_view(), name='superadmin-notification'),
]
