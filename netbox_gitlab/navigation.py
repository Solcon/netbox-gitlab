from extras.plugins import PluginMenuItem

menu_items = (
    PluginMenuItem(
        link='plugins:netbox_gitlab:export-inventory',
        link_text='Export inventory',
        permissions=[
            'netbox_gitlab.export_device',
        ],
    ),
    PluginMenuItem(
        link='plugins:netbox_gitlab:export-all',
        link_text='Export everything',
        permissions=[
            'netbox_gitlab.export_device',
            'netbox_gitlab.export_interface',
        ],
    ),
)
