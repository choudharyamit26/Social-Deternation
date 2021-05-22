from django.urls import path
from django.contrib.auth.views import LogoutView, PasswordResetDoneView, PasswordResetCompleteView
from .views import LoginView, Dashboard, SubscriptionView, SurvivorsView, CardInformationView, MyProfileView, \
    PasswordResetView, PasswordResetConfirmView, SuperAdminLogin, SuperAdminDashboard, CustomerManagementView, \
    SuperAdminLogout, PasswordChangeView, PasswordChangeDoneView, SuperAdminSupscriptionView, SuperAdminClientsView, \
    SuperAdminServiceProviders, SuperAdminProvidersCategory, SuperAdminAssaultFormView, SuperAdminAssaultRecords

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
    path("superadmin-subscription-plan/", SuperAdminSupscriptionView.as_view(), name="superadmin-subscription-plan"),
    path("superadmin-clients/", SuperAdminClientsView.as_view(), name="superadmin-clients"),
    path("superadmin-service-providers/", SuperAdminServiceProviders.as_view(), name="superadmin-service-providers"),
    path("superadmin-assault-form/", SuperAdminAssaultFormView.as_view(), name="superadmin-assault-form"),
    path("superadmin-assault-records/", SuperAdminAssaultRecords.as_view(), name="superadmin-assault-records"),
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
]
