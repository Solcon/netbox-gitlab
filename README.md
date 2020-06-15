# GitLab export to Ansible Inventory for NetBox

## Compatibility

This plugin in compatible with [NetBox](https://netbox.readthedocs.org/) 2.8 and later.

## Installation

First, add `netbox_gitlab` to your `/opt/netbox/local_requirements.txt` file. Create it if it doesn't exist.

If you are using a local version of the plugin, for example for development, add `-e /opt/path/to/plugin` instead.

Then enable the plugin in `/opt/netbox/netbox/netbox/configuration.py`, like:

```python
PLUGINS = [
    'netbox_gitlab',
]
```

The plugin needs to be configured. The following settings are required:

```python
PLUGINS_CONFIG = {
    'netbox_gitlab': {
        'url': 'https://gitlab.example.com',
        'private_token': 'aBcDeFgHiJkLmNoPqRsTuVwXyZ',
        'project_path': 'group/project',
    },
}
```

This example would correspond to the project at `https://gitlab.example.com/group/project`.

And finally run `/opt/netbox/upgrade.sh`. This will download and install the plugin and update the database when
necessary. Don't forget to run `sudo systemctl restart netbox netbox-rq` like `upgrade.sh` tells you!

## Usage

This plugin uses NetBox export templates to generate the files that are put into the git repository. The output of these templates is parsed as YAML, but JSON output is also accepted (as all valid JSON is also valid YAML). Generating JSON can be more convenient because of the more relaxed parsing of indentation.

By default this plugin looks for these export templates:

| Content type     | Name               | Purpose                                               |
|------------------|--------------------|-------------------------------------------------------|
| dcim > device    | Ansible Inventory  | A single file listing all devices                     |
| dcim > device    | Ansible Device     | One file per device with device-level configuration   |
| dcim > interface | Ansible Interfaces | One file per device with its interface configurations |
 
The output sent to GitLab for the inventory is exactly what the export template produces. The output sent to GitLab for device and interface configurations is always YAML with all the empty variables omitted. This makes it easier when writing export templates while still keeping the output compact. This in turn helps to keep Ansible a bit faster by reducing the time spent on parsing the YAML. 

For the devices export template this plugin expects the generated YAML/JSON to be a mapping with the device name as the key. When a device is part of a virtual chassis all members of the virtual chassis will be included.

For the interfaces export template this plugin expects the generated YAML/JSON to be a mapping with the interface name as the key.

Examples of export templates are provided in the git repository of this plugin.
