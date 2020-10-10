from django.urls import path

from netbox_gitlab.views import ExportDeviceView, ExportInterfacesView, ExportInventoryView

urlpatterns = [
    path(route='export-inventory/',
         view=ExportInventoryView.as_view(),
         name='export-inventory'),
    path(route='export-device/<int:device_id>/',
         view=ExportDeviceView.as_view(),
         name='export-device'),
    path(route='export-interfaces/<int:device_id>/',
         view=ExportInterfacesView.as_view(),
         name='export-interfaces'),
]
