# This file contains some ugly hacks to help with some export templates
# Don't do this at home

from django.db.models import Q

from dcim.models import Device
from ipam.models import VLAN, VRF


def vlans(self):
    device = self

    tagged_vlan_ids = list(device.vc_interfaces.values_list('untagged_vlan', flat=True))
    untagged_vlan_ids = list(device.vc_interfaces.values_list('tagged_vlans', flat=True))

    return VLAN.objects.filter(Q(id__in=tagged_vlan_ids) | Q(id__in=untagged_vlan_ids))


def vrfs(self):
    device = self

    vrf_ids = list(device.vc_interfaces.values_list('ip_addresses__vrf', flat=True))
    return VRF.objects.filter(id__in=vrf_ids)


# Add the vlans and vrfs properties to the Device class
Device.vlans = property(vlans)
Device.vrfs = property(vrfs)
