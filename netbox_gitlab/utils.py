import hashlib
import itertools
from difflib import HtmlDiff
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import QuerySet
from django.utils.safestring import mark_safe
from gitlab import Gitlab, GitlabCreateError, GitlabError, GitlabGetError, GitlabHttpError
from gitlab.utils import clean_str_id
from gitlab.v4.objects import ProjectMergeRequest
from yaml import SafeDumper, SafeLoader

from dcim.models import Device, Interface
from extras.models import ExportTemplate
from netbox_gitlab.models import TraceElement


class GitLabDumper(SafeDumper):
    pass


# noinspection PyAbstractClass
class GitLabLoader(SafeLoader):
    pass


def clean_value(value):
    if isinstance(value, dict):
        value = clean_dict(value)
    elif isinstance(value, list):
        clean_values = [clean_value(item) for item in value]
        value = []
        for item in clean_values:
            if item in value:
                continue
            value.append(item)

    if value in ('', [], {}):
        return None

    return value


def clean_dict(data: Dict[str, Any]) -> dict:
    out = {}

    for key, value in data.items():
        value = clean_value(value)
        if value is None:
            continue

        out[key] = value

    return out


def generate_inventory() -> Optional[str]:
    config = settings.PLUGINS_CONFIG['netbox_gitlab']
    devices_template = config['inventory_template']
    try:
        device_model_ct = ContentType.objects.get_for_model(Device)
        export_template = ExportTemplate.objects.get(content_type=device_model_ct,
                                                     name=devices_template)

        # Re-fetch device with prefetch
        devices = Device.objects.prefetch_related(
            *settings.PLUGINS_CONFIG['netbox_gitlab']['device_prefetch']
        )
        output = export_template.render(devices)
    except ExportTemplate.DoesNotExist:
        return

    return output


def generate_devices(devices: Iterable[Device]):
    config = settings.PLUGINS_CONFIG['netbox_gitlab']
    devices_template = config['devices_template']
    try:
        device_model_ct = ContentType.objects.get_for_model(Device)
        export_template = ExportTemplate.objects.get(content_type=device_model_ct,
                                                     name=devices_template)

        # Re-fetch device with prefetch
        device = Device.objects.filter(pk__in=[device.pk for device in devices]).prefetch_related(
            *settings.PLUGINS_CONFIG['netbox_gitlab']['device_prefetch']
        )
        output = export_template.render(device)
    except ExportTemplate.DoesNotExist:
        return

    # Parse as YAML
    data = yaml.load(output, Loader=GitLabLoader)
    if data:
        data = clean_value(data)

    return data


def generate_device_interfaces(device: Device):
    generate_missing_traces(device.vc_interfaces.all())
    interfaces = device.vc_interfaces.prefetch_related(
        *settings.PLUGINS_CONFIG['netbox_gitlab']['interfaces_prefetch']
    )
    return generate_interfaces(interfaces)


def generate_interfaces(interfaces: Iterable[Interface]):
    config = settings.PLUGINS_CONFIG['netbox_gitlab']
    interfaces_template = config['interfaces_template']
    try:
        interface_model_ct = ContentType.objects.get_for_model(Interface)
        export_template = ExportTemplate.objects.get(content_type=interface_model_ct,
                                                     name=interfaces_template)
        output = export_template.render(interfaces)
    except ExportTemplate.DoesNotExist:
        return

    # Parse as YAML
    data = yaml.load(output, Loader=GitLabLoader)
    if data:
        data = clean_value(data)

    return data


def extract_interfaces(data) -> Optional[dict]:
    config = settings.PLUGINS_CONFIG['netbox_gitlab']
    key = config['interfaces_key']
    if isinstance(data, dict) and key in data and isinstance(data[key], dict):
        return data[key]

    return {}


def expand_virtual_chassis(device: Device) -> Tuple[Optional[Device], List[Device]]:
    devices = []

    # Start with a single device, and assume it's its own master
    # Still called "master" to maintain consistency with NetBox
    master = device
    devices.append(device)

    # Add children of virtual chassis and determine the real master
    if device.virtual_chassis:
        master = device.virtual_chassis.master
        for child in device.virtual_chassis.members.all():
            if child not in devices:
                devices.append(child)

    return master, devices


def update_trace_cache(interface: Interface):
    path = interface.trace()[0]
    elements = [TraceElement(from_interface=interface, step=step, element=element)
                for step, element in enumerate(itertools.chain(*path))
                if element is not None]

    with transaction.atomic():
        TraceElement.objects.filter(from_interface=interface).delete()
        TraceElement.objects.bulk_create(elements)


def generate_missing_traces(interfaces: QuerySet):
    existing = list(TraceElement.objects.values_list('from_interface', flat=True))
    for interface in interfaces.exclude(pk__in=existing):
        update_trace_cache(interface)


def make_diff(gitlab_data: str, netbox_data: str, differ: HtmlDiff = None) -> str:
    differ = differ or HtmlDiff(tabsize=2)
    diff = mark_safe(differ.make_table(
        fromdesc='GitLab',
        fromlines=gitlab_data.splitlines(),
        todesc='NetBox',
        tolines=netbox_data.splitlines(),
    ))
    return diff


def make_diffs(devices: Iterable[Device], gitlab_data: Dict[str, Any], netbox_data: Dict[str, Any]) -> Dict[str, str]:
    differ = HtmlDiff(tabsize=2)
    diffs = {}
    for device in devices:
        gitlab_interfaces = gitlab_data[device.name]
        netbox_interfaces = netbox_data[device.name]

        if not gitlab_interfaces and not netbox_interfaces:
            continue

        old_fragment = yaml.dump(gitlab_interfaces, Dumper=GitLabDumper, default_flow_style=False)
        new_fragment = yaml.dump(netbox_interfaces, Dumper=GitLabDumper, default_flow_style=False)
        diffs[device.name] = make_diff(gitlab_data=old_fragment,
                                       netbox_data=new_fragment,
                                       differ=differ)

    return diffs


class GitLabMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.config = settings.PLUGINS_CONFIG['netbox_gitlab']

        try:
            self.gitlab = Gitlab(url=self.config['url'],
                                 private_token=self.config['private_token'],
                                 ssl_verify=self.config['ssl_verify'])
            self.project = self.gitlab.projects.get(id=self.config['project_path'])
            self.gitlab_error = None
        except GitlabError as e:
            self.gitlab = None
            self.project = None
            self.gitlab_error = e.error_message

    def branch_exists(self, branch: str) -> bool:
        try:
            self.project.branches.get(branch)
            return True
        except GitlabGetError as e:
            if e.response_code == 404:
                # Branch doesn't exist yet
                return False
            else:
                raise

    def get_hash_from_repo(self, branch: str, filename: str) -> Optional[str]:
        path = '{}/{}'.format(self.project.files.path, clean_str_id(filename))
        try:
            file_data = self.gitlab.http_request(verb='HEAD', path=path, ref=branch)
        except GitlabHttpError:
            return None

        return file_data.headers['X-Gitlab-Content-Sha256']

    def get_gitlab_inventory(self, branch: str) -> Optional[str]:
        try:
            file_data = self.project.files.get(
                file_path=self.config['inventory_file'],
                ref=branch,
            )
            return file_data.decode().decode('utf-8')
        except GitlabError:
            return

    def get_gitlab_device(self, branch: str, device: Device):
        try:
            file_data = self.project.files.get(
                file_path=self.config['device_file'].format(device=device),
                ref=branch,
            )
            return yaml.load(file_data.decode(), Loader=GitLabLoader)
        except GitlabError:
            return {}

    def get_gitlab_interfaces(self, branch: str, device: Device):
        try:
            file_data = self.project.files.get(
                file_path=self.config['interfaces_file'].format(device=device),
                ref=branch,
            )
            return yaml.load(file_data.decode(), Loader=GitLabLoader)
        except GitlabError:
            return None


class GitLabCommitMixin(GitLabMixin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.commit_files = {}

    def gitlab_add_file(self, filename: str, content: str):
        self.commit_files[filename] = content

    def commit(self, user, branch: str) -> Tuple[int, Optional[ProjectMergeRequest]]:
        base_branch = self.config['main_branch']
        author_name = "{user.first_name} {user.last_name}".format(user=user).strip() or user.username
        author_email = user.email

        gitlab_data = {
            'branch': branch,
            'commit_message': 'Update router config from Netbox',
            'author_name': author_name,
            'author_email': author_email,
            'actions': []
        }

        # Determine whether we are creating a new branch or updating an existing one
        branch_exists = self.branch_exists(branch)
        if branch_exists:
            ref_branch = branch
        else:
            # We are creating a new branch, so use the base branch when comparing content
            ref_branch = base_branch
            gitlab_data['start_branch'] = base_branch

        # Build the list of updates
        for filename, content in self.commit_files.items():
            repo_hash = self.get_hash_from_repo(ref_branch, filename)
            if not repo_hash:
                # No hash = no file, so create a new one
                gitlab_data['actions'].append({
                    'action': 'create',
                    'file_path': filename,
                    'content': content,
                })
            else:
                # Calculate the hash of the new version
                my_hash = hashlib.sha256(content.encode('utf8')).hexdigest()
                if my_hash != repo_hash:
                    # File exists, but hash is different
                    gitlab_data['actions'].append({
                        'action': 'update',
                        'file_path': filename,
                        'content': content,
                    })
                else:
                    # File exists and has the same hash, don't update
                    pass

        if gitlab_data['actions']:
            self.project.commits.create(gitlab_data)

            # Create a merge request when we created a branch
            create_merge_request = not branch_exists
        else:
            # We didn't do anything, so no sense creating a merge request
            create_merge_request = False

        merge_req = None
        if create_merge_request:
            try:
                merge_req = self.project.mergerequests.create({
                    'source_branch': branch,
                    'target_branch': base_branch,
                    'title': 'Merge Netbox updates from ' + branch,
                    'remove_source_branch': True,
                    'allow_collaboration': True,
                })
            except GitlabCreateError as e:
                if e.response_code == 409:
                    # Already exists, which is fine
                    pass
                else:
                    raise
        else:
            # See if there is a merge request for this branch
            merge_reqs = self.project.mergerequests.list(
                state='opened',
                source_branch=branch,
                target_branch=base_branch,
            )
            if len(merge_reqs) == 1:
                merge_req = merge_reqs[0]

        return len(gitlab_data['actions']), merge_req


def dict_changes(dict1: dict, dict2: dict) -> list:
    changes = []
    for key in sorted(set(dict1.keys()) | set(dict2.keys())):
        dict1_value = dict1.get(key)
        dict2_value = dict2.get(key)

        # Don't bother if both values evaluate to False
        if not dict1_value and not dict2_value:
            continue

        if isinstance(dict1_value, dict) and isinstance(dict2_value, dict):
            # Both are dicts, dive in
            sub_changes = dict_changes(dict1_value, dict2_value)
            for value in sub_changes:
                changes.append(f'{key}.{value}')

        elif dict1_value != dict2_value:
            changes.append(key)

    return changes
