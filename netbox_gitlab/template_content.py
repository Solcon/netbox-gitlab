from difflib import HtmlDiff

import yaml
from django.contrib.auth.context_processors import PermWrapper
from django.http import HttpRequest
from django.utils.functional import cached_property
from django.utils.safestring import mark_safe

from dcim.models import Device
from extras.plugins import PluginTemplateExtension
from netbox_gitlab.utils import (GitLabDumper, GitLabMixin, dict_changes, expand_virtual_chassis, extract_interfaces,
                                 generate_device_interfaces, generate_devices)


# noinspection PyAbstractClass
class SyncInfo(GitLabMixin, PluginTemplateExtension):
    model = 'dcim.device'

    def __init__(self, context):
        super().__init__(context)

        self.device = self.context['object']  # type: Device
        self.request = self.context['request']  # type: HttpRequest

    @cached_property
    def device_data(self):
        # Still called "master" to maintain consistency with NetBox
        master, devices = expand_virtual_chassis(self.device)
        netbox_devices = generate_devices(devices)

        return devices, netbox_devices

    def left_page(self):
        if not self.project:
            return ''

        # Skip interfaces if device template returns False
        devices, netbox_devices = self.device_data
        if isinstance(netbox_devices, dict) \
                and self.device.name in netbox_devices \
                and netbox_devices[self.device.name] is False:
            return ''

        branch = self.config['main_branch']
        gitlab_interfaces_data = self.get_gitlab_interfaces(branch, self.device)
        gitlab_interfaces = extract_interfaces(gitlab_interfaces_data) or {}

        netbox_interfaces_data = generate_device_interfaces(self.device)
        netbox_interfaces = extract_interfaces(netbox_interfaces_data)
        if not netbox_interfaces:
            return ''

        differ = HtmlDiff(tabsize=2)

        interface_changes = {}
        for name, data in netbox_interfaces.items():
            gitlab_interface = gitlab_interfaces.get(name, {})
            netbox_interface = netbox_interfaces.get(name, {})

            changes = dict_changes(netbox_interface, gitlab_interface)
            if changes:
                gitlab_yaml = yaml.dump(gitlab_interface, Dumper=GitLabDumper, default_flow_style=False)
                netbox_yaml = yaml.dump(netbox_interface, Dumper=GitLabDumper, default_flow_style=False)

                interface_changes[name] = {
                    'fields': changes,
                    'diff': mark_safe(differ.make_table(
                        fromdesc='GitLab',
                        fromlines=gitlab_yaml.splitlines(),
                        todesc='NetBox',
                        tolines=netbox_yaml.splitlines(),
                    )),
                    'gitlab_yaml': gitlab_yaml,
                    'gitlab_empty': not gitlab_interface,
                    'netbox_yaml': netbox_yaml,
                    'netbox_empty': not netbox_interface,
                }
            else:
                interface_changes[name] = None

        return self.render('netbox_gitlab/device/update_interface_table.html', {
            'interface_changes': interface_changes,
            'device': devices[0],
            'perms': PermWrapper(self.request.user),
        })

    def right_page(self):
        if not self.project:
            if self.gitlab_error:
                return self.render('netbox_gitlab/gitlab_error.html', {
                    'message': self.gitlab_error
                })
            else:
                return ''

        # Skip if device template returns False
        devices, netbox_devices = self.device_data
        if not isinstance(netbox_devices, dict) \
                or self.device.name not in netbox_devices \
                or netbox_devices[self.device.name] is False:
            return ''

        branch = self.config['main_branch']
        gitlab_devices = {device.name: self.get_gitlab_device(branch, device)
                          for device in devices}

        # Get the main device
        gitlab_device = gitlab_devices.get(self.device.name, {})
        netbox_device = netbox_devices.get(self.device.name, {})

        differ = HtmlDiff(tabsize=2)

        changes = dict_changes(gitlab_device, netbox_device)
        if changes:
            gitlab_yaml = yaml.dump(gitlab_devices, Dumper=GitLabDumper, default_flow_style=False)
            netbox_yaml = yaml.dump(netbox_devices, Dumper=GitLabDumper, default_flow_style=False)

            device_changes = {
                'fields': changes,
                'diff': mark_safe(differ.make_table(
                    fromdesc='GitLab',
                    fromlines=gitlab_yaml.splitlines(),
                    todesc='NetBox',
                    tolines=netbox_yaml.splitlines(),
                )),
                'gitlab_yaml': gitlab_yaml,
                'netbox_yaml': netbox_yaml,
            }
        else:
            device_changes = None

        return self.render('netbox_gitlab/device/device_info.html', {
            'empty': not gitlab_device,
            'device_changes': device_changes,
            'perms': PermWrapper(self.request.user),
        })


template_extensions = [SyncInfo]
