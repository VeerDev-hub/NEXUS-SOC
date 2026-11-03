from django.urls import path

from .metrics import SocMetricsView
from .views import DashboardOverviewView


urlpatterns = [
    path("dashboard/overview/", DashboardOverviewView.as_view(), name="dashboard-overview"),
    path("dashboard/soc-metrics/", SocMetricsView.as_view(), name="dashboard-soc-metrics"),
]

