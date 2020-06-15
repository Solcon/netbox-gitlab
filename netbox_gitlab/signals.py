import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from dcim.models import Cable, Interface
from netbox_gitlab.utils import update_trace_cache

logger = logging.getLogger('netbox_gitlab')


@receiver(post_save, sender=Cable)
def update_connected_endpoints(instance, **_kwargs):
    """
    When a Cable is saved, update the trace cache for all its endpoints
    """
    # Update any endpoints for this Cable.
    endpoints = instance.termination_a.get_path_endpoints() + instance.termination_b.get_path_endpoints()
    for endpoint in endpoints:
        if isinstance(endpoint, Interface):
            update_trace_cache(endpoint)


@receiver(post_save, sender=Interface)
def update_trace(instance, **_kwargs):
    """
    When an Interface is saved and the connection_status is None this can indicate a deleted cable. Rebuild the
    trace cache. May be optimised later.
    """
    if instance.connection_status is None:
        update_trace_cache(instance)
