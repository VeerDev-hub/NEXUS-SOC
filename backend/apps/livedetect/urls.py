from django.urls import path

from .views import EntityProfileDetailView, EntityProfileListView

urlpatterns = [
    path("ueba/profiles/", EntityProfileListView.as_view(), name="ueba-profiles"),
    path("ueba/profiles/<int:pk>/", EntityProfileDetailView.as_view(), name="ueba-profile-detail"),
]
