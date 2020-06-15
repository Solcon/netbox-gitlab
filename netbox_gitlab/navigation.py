from extras.plugins import PluginMenuItem

menu_items = (
    PluginMenuItem(
        link='plugins:netbox_gitlab:export-inventory',
        link_text='Export inventory',
        permissions=[
            'netbox_gitlab.export_device',
        ]
    ),
)
