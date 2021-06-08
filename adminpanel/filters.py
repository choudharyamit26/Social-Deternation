# import django_filters
# from django_filters import DateFilter, CharFilter
# from .models import SubscriptionPlan
#
#
# class OrganizationFilter(django_filters.FilterSet):
#     # organization_name = CharFilter(field_name='organization_name__organization_name')
#     # first_name = CharFilter(field_name='organization_name__first_name')
#     # last_name = CharFilter(field_name='organization_name__last_name')
#     # email = CharFilter(field_name='organization_name__email')
#     # client_code = CharFilter(field_name='organization_name__client_code')
#     # mobile_number = CharFilter(field_name='organization_name__mobile_number')
#     from_date = DateFilter(field_name='organization_name__created_at', lookup_expr='gte', label='From Date')
#     to_date = DateFilter(field_name='organization_name__created_at', lookup_expr='lte', label='To Date')
#
#     class Meta:
#         model = SubscriptionPlan
#         fields = (
#             'organization_name__organization_name', 'organization_name__first_name', 'organization_name__last_name',
#             'organization_name__email', 'organization_name__client_code', 'organization_name__mobile_number',
#             'from_date', 'to_date')
