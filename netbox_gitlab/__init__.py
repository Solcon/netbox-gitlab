VERSION = '0.5'

try:
    from extras.plugins import PluginConfig
except ImportError:
    # Dummy for when importing outside of netbox
    class PluginConfig:
        pass


class NetBoxGitLabConfig(PluginConfig):
    name = 'netbox_gitlab'
    verbose_name = 'GitLab Ansible export'
    version = VERSION
    author = 'Sander Steffann'
    author_email = 'sander.steffann@isp.solcon.nl'
    description = 'GitLab export to Ansible Inventory for NetBox'
    base_url = 'gitlab'
    required_settings = [
        'url',
        'private_token',
        'project_path',
    ]
    default_settings = {
        'main_branch': 'main',
        'ssl_verify': True,

        'inventory_file': 'hosts.ini',
        'device_file': 'host_vars/{device.name}/generated-device.yaml',
        'interfaces_file': 'host_vars/{device.name}/generated-interfaces.yaml',

        'inventory_template': 'Ansible Inventory',
        'devices_template': 'Ansible Device',
        'interfaces_template': 'Ansible Interfaces',
        'interfaces_key': 'interfaces',

        'device_prefetch': [
            'interfaces__ip_addresses',
            'interfaces__ip_addresses__tags',
            'interfaces__ip_addresses__vrf',
        ],
        'interfaces_prefetch': [
            'device',
            'tags',
            'lag',
            'ip_addresses',
            'ip_addresses__tags',
            'ip_addresses__vrf',
            'untagged_vlan',
            'tagged_vlans',
            '_connected_interface',
            '_connected_interface__device',
            '_connected_circuittermination',
            '_connected_circuittermination__circuit',
            '_connected_circuittermination__circuit__provider',
            '_connected_circuittermination__circuit__type',
            'trace_elements',
            'trace_elements___cable',
            'trace_elements___cable__termination_a_type',
            'trace_elements___cable__termination_b_type',
            'trace_elements___front_port',
            'trace_elements___front_port__device',
            'trace_elements___rear_port',
            'trace_elements___rear_port__device',
            'trace_elements___interface',
            'trace_elements___interface__device',
            'trace_elements___circuit_termination',
            'trace_elements___circuit_termination__circuit',
            'trace_elements___circuit_termination__circuit__type',
            'trace_elements___circuit_termination__circuit__provider',
        ],
    }

    def ready(self):
        super().ready()

        from . import hacks
        from . import signals


config = NetBoxGitLabConfig
