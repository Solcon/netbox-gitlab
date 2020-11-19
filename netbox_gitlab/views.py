import copy

import yaml
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core import signing
from django.core.signing import SignatureExpired
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.safestring import mark_safe
from django.views import View

from dcim.models import Device, Interface
from netbox_gitlab.forms import (GitLabBranchForm, GitLabBranchInterfacesForm, GitLabCommitDeviceForm,
                                 GitLabCommitInterfacesForm,
                                 GitLabCommitInventoryForm)
from netbox_gitlab.utils import (GitLabCommitMixin, GitLabDumper, expand_virtual_chassis, extract_interfaces,
                                 generate_devices, generate_interfaces, generate_inventory, make_diff, make_diffs)
from utilities.views import GetReturnURLMixin


class ExportInventoryView(GitLabCommitMixin, PermissionRequiredMixin, GetReturnURLMixin, View):
    permission_required = 'netbox_gitlab.export_device'

    def ask_branch(self, request) -> HttpResponse:
        # Collect all the branches we can push to
        branches = [branch.name for branch in self.project.branches.list() if branch.can_push]

        form = GitLabBranchForm()

        return render(request, 'netbox_gitlab/ask_branch.html', {
            'export_type': 'Inventory',
            'form': form,
            'branches': branches,
            'return_url': self.get_return_url(request),
        })

    def show_diff(self, request: HttpRequest, form: GitLabCommitInventoryForm = None) -> HttpResponse:
        # If we don't have a GitLab project we can't do anything
        if not self.project:
            messages.error(self.request, f"GitLab server error: {self.gitlab_error}")
            return redirect('home')

        branch = request.POST['branch'] \
            if self.branch_exists(str(request.POST['branch'])) \
            else self.config['main_branch']
        gitlab_inventory = self.get_gitlab_inventory(branch) or ''
        netbox_inventory = generate_inventory()
        if not netbox_inventory:
            return redirect('home')

        diff = make_diff(
            gitlab_data=gitlab_inventory,
            netbox_data=netbox_inventory
        )

        # Collect all the branches we can push to
        branches = [branch.name for branch in self.project.branches.list() if branch.can_push]

        update = signing.dumps(netbox_inventory, salt='netbox_gitlab.inventory', compress=True)

        if not form:
            form = GitLabCommitInventoryForm(initial={
                'update': update,
            })
        else:
            # Override the bound data
            form.data['update'] = update

        return render(request, 'netbox_gitlab/export_inventory.html', {
            'branch': request.POST['branch'],
            'diff': diff,
            'form': form,
            'branches': branches,
            'return_url': self.get_return_url(request),
        })

    def get(self, request: HttpRequest) -> HttpResponse:
        return self.ask_branch(request)

    def post(self, request: HttpRequest) -> HttpResponse:
        # Check is branch name is valid
        branch_form = GitLabBranchForm(data=request.POST)
        if not branch_form.is_valid():
            return self.ask_branch(request)

        form = GitLabCommitInventoryForm(data=copy.copy(request.POST))
        if not form.is_valid():
            return self.show_diff(request, form)

        try:
            new_gitlab_data = signing.loads(form.cleaned_data['update'], salt='netbox_gitlab.inventory', max_age=900)
        except SignatureExpired:
            messages.warning(request, "Update expired, please submit again")
            return self.show_diff(request, form)

        # We appear to have new gitlab data!
        filename = self.config['inventory_file']
        self.gitlab_add_file(filename, new_gitlab_data)

        branch = form.cleaned_data['branch']
        changes, merge_req = self.commit(user=self.request.user, branch=branch)

        if not changes:
            messages.warning(self.request, f"Nothing has changed (changes already committed to branch {branch}?)")
        elif merge_req:
            messages.success(self.request, mark_safe(
                f'Inventory changed in branch {branch}, '
                f'<a target="_blank" href="{merge_req.web_url}">merge request {merge_req.iid}</a> created'
            ))
        else:
            messages.success(self.request, f"Inventory changed in branch {branch}")

        return redirect(self.get_return_url(request))


class ExportDeviceView(GitLabCommitMixin, PermissionRequiredMixin, GetReturnURLMixin, View):
    permission_required = 'netbox_gitlab.export_device'

    def ask_branch(self, request, device: Device) -> HttpResponse:
        # Collect all the branches we can push to
        branches = [branch.name for branch in self.project.branches.list() if branch.can_push]

        form = GitLabBranchForm()

        return render(request, 'netbox_gitlab/ask_branch.html', {
            'export_type': 'Device',
            'device': device,
            'form': form,
            'branches': branches,
            'return_url': self.get_return_url(request, device),
        })

    def show_diff(self, request: HttpRequest, base_device: Device, form: GitLabCommitDeviceForm = None) -> HttpResponse:
        # Get all the relevant devices
        # Still called "master" to maintain consistency with NetBox
        master, devices = expand_virtual_chassis(base_device)

        # If we don't have a GitLab project we can't do anything
        if not self.project:
            messages.error(self.request, f"GitLab server error: {self.gitlab_error}")
            return redirect(self.get_return_url(request, base_device))

        branch = request.POST['branch'] \
            if self.branch_exists(str(request.POST['branch'])) \
            else self.config['main_branch']
        gitlab_devices = {device.name: self.get_gitlab_device(branch, device)
                          for device in devices}

        netbox_devices = generate_devices(devices)

        # Create the diffs for the selected devices
        diffs = make_diffs(
            devices=devices,
            gitlab_data=gitlab_devices,
            netbox_data=netbox_devices
        )

        # Construct the new contents of the whole file
        new_gitlab_data = {name: yaml.dump(netbox_device,
                                           Dumper=GitLabDumper, sort_keys=False, default_flow_style=False)
                           for name, netbox_device in netbox_devices.items()}

        update = signing.dumps(new_gitlab_data, salt='netbox_gitlab.devices', compress=True)

        if not form:
            form = GitLabCommitDeviceForm(initial={
                'update': update,
            })
        else:
            # Override the bound data
            form.data['update'] = update

        return render(request, 'netbox_gitlab/export_device.html', {
            'branch': request.POST['branch'],
            'device': base_device,
            'diffs': diffs,
            'form': form,
            'return_url': self.get_return_url(request, base_device),
        })

    def get(self, request: HttpRequest, device_id: int) -> HttpResponse:
        base_device = get_object_or_404(Device, pk=device_id)
        return self.ask_branch(request, base_device)

    def post(self, request: HttpRequest, device_id: int) -> HttpResponse:
        base_device = get_object_or_404(Device, pk=device_id)

        # Check is branch name is valid
        branch_form = GitLabBranchForm(data=request.POST)
        if not branch_form.is_valid():
            return self.ask_branch(request, base_device)

        # Check if the rest of the form is valid
        form = GitLabCommitDeviceForm(data=copy.copy(request.POST))
        if not form.is_valid():
            return self.show_diff(request, base_device, form)

        try:
            new_gitlab_data = signing.loads(form.cleaned_data['update'], salt='netbox_gitlab.devices', max_age=900)
        except SignatureExpired:
            messages.warning(request, "Update expired, please submit again")
            return self.show_diff(request, base_device, form)

        # We appear to have new gitlab data!
        for device_name, content in new_gitlab_data.items():
            device = get_object_or_404(Device, name=device_name)
            filename = self.config['device_file'].format(device=device)
            self.gitlab_add_file(filename, content)

        branch = form.cleaned_data['branch']
        changes, merge_req = self.commit(user=self.request.user, branch=branch)

        if not changes:
            messages.warning(self.request, f"Nothing has changed (changes already committed to branch {branch}?)")
        elif merge_req:
            messages.success(self.request, mark_safe(
                f'{changes} file(s) changed in branch {branch}, '
                f'<a target="_blank" href="{merge_req.web_url}">merge request {merge_req.iid}</a> created'
            ))
        else:
            messages.success(self.request, f"{changes} file(s) changed in branch {branch}")

        return redirect(self.get_return_url(request, base_device))


class ExportInterfacesView(GitLabCommitMixin, PermissionRequiredMixin, GetReturnURLMixin, View):
    permission_required = 'netbox_gitlab.export_interface'

    # noinspection PyMethodMayBeStatic,PyUnusedLocal
    def get(self, request, device_id: int) -> HttpResponse:
        return redirect('home')

    def ask_branch(self, request, device: Device) -> HttpResponse:
        interface_ids = request.POST.getlist('pk')

        # Collect all the branches we can push to
        branches = [branch.name for branch in self.project.branches.list() if branch.can_push]

        form = GitLabBranchInterfacesForm(initial={
            'pk': interface_ids,
        })

        return render(request, 'netbox_gitlab/ask_branch.html', {
            'export_type': 'Interfaces',
            'device': device,
            'form': form,
            'branches': branches,
            'return_url': self.get_return_url(request, device),
        })

    def show_diff(self, request, base_device: Device, form: GitLabCommitInterfacesForm = None) -> HttpResponse:
        interface_ids = request.POST.getlist('pk')

        # Get all the relevant devices
        master, devices = expand_virtual_chassis(base_device)

        # Get all the relevant interfaces
        interfaces = Interface.objects.filter(pk__in=interface_ids, device__in=devices).order_by('_name')
        if not interfaces:
            messages.warning(request, "No interfaces were selected for export, regenerating whole file")
            interfaces = Interface.objects.filter(device__in=devices).order_by('_name')
            regenerate = True
        else:
            regenerate = False

        interface_lookup = {interface.name: interface for interface in interfaces}

        # Prepare a new update
        branch = request.POST['branch'] \
            if self.branch_exists(str(request.POST['branch'])) \
            else self.config['main_branch']
        gitlab_data = {device.name: self.get_gitlab_interfaces(branch, device) for device in devices}
        gitlab_interfaces = {device_name: extract_interfaces(device_interfaces)
                             for device_name, device_interfaces in gitlab_data.items()}

        netbox_data = generate_interfaces(interfaces)
        netbox_plain_interfaces = extract_interfaces(netbox_data)
        if not netbox_plain_interfaces:
            return redirect(self.get_return_url(request, base_device))

        # Extract the interfaces we are going to change from the GitLab data for the diff
        orig_gitlab_interfaces = {device_name: {
            if_name: if_data
            for if_name, if_data in device_interfaces.items()
            if regenerate or if_name in netbox_plain_interfaces
        } for device_name, device_interfaces in gitlab_interfaces.items()}

        if regenerate:
            gitlab_interfaces = {device.name: {} for device in devices}

        # Update GitLab data with new NetBox data
        netbox_device_interfaces = {device.name: {} for device in devices}
        for if_name, if_data in netbox_plain_interfaces.items():
            interface = interface_lookup[if_name]
            gitlab_interfaces[master.name][if_name] = if_data
            gitlab_interfaces[interface.device.name][if_name] = if_data

            netbox_device_interfaces[master.name][if_name] = if_data
            netbox_device_interfaces[interface.device.name][if_name] = if_data

        # Construct the new contents of the whole file
        config = settings.PLUGINS_CONFIG['netbox_gitlab']
        key = config['interfaces_key']

        new_gitlab_data = {name: yaml.dump({key: netbox_interfaces},
                                           Dumper=GitLabDumper, sort_keys=False, default_flow_style=False)
                           for name, netbox_interfaces in gitlab_interfaces.items()}
        update = signing.dumps(new_gitlab_data, salt='netbox_gitlab.interfaces', compress=True)

        if not form:
            form = GitLabCommitInterfacesForm(initial={
                'pk': interface_ids,
                'branch': request.POST['branch'],
                'update': update,
            })
        else:
            # Override the bound data
            form.data['update'] = update

        # Create the diffs for the selected interfaces
        diffs = make_diffs(
            devices=devices,
            gitlab_data=orig_gitlab_interfaces,
            netbox_data=netbox_device_interfaces
        )

        return render(request, 'netbox_gitlab/export_interfaces.html', {
            'branch': request.POST['branch'],
            'device': base_device,
            'diffs': diffs,
            'form': form,
            'return_url': self.get_return_url(request, base_device),
        })

    def do_commit(self, request, base_device) -> HttpResponse:
        # Use a copy of the POST data so we can manipulate it later
        form = GitLabCommitInterfacesForm(copy.copy(request.POST))
        if form.is_valid():
            try:
                new_gitlab_data = signing.loads(request.POST['update'], salt='netbox_gitlab.interfaces', max_age=900)
            except SignatureExpired:
                messages.warning(request, "Update expired, please submit again")
                return self.show_diff(request, base_device, form)
        else:
            # Invalid form data, show form again
            messages.warning(request, "Form error, please submit again")
            return self.show_diff(request, base_device, form)

        # We appear to have new gitlab data!
        for device_name, content in new_gitlab_data.items():
            device = get_object_or_404(Device, name=device_name)
            filename = self.config['interfaces_file'].format(device=device)
            self.gitlab_add_file(filename, content)

        branch = form.cleaned_data['branch']
        changes, merge_req = self.commit(user=self.request.user, branch=branch)

        if not changes:
            messages.warning(self.request, f"Nothing has changed (changes already committed to branch {branch}?)")
        elif merge_req:
            messages.success(self.request, mark_safe(
                f'{changes} file(s) changed in branch {branch}, '
                f'<a target="_blank" href="{merge_req.web_url}">merge request {merge_req.iid}</a> open'
            ))
        else:
            messages.success(self.request, f"{changes} file(s) changed in branch {branch}")

        return redirect(self.get_return_url(request, base_device))

    def post(self, request, device_id: int) -> HttpResponse:
        device = get_object_or_404(Device, pk=device_id)

        # If we don't have a GitLab project we can't do anything
        if not self.project:
            messages.error(self.request, f"GitLab server error: {self.gitlab_error}")
            return redirect(self.get_return_url(request, device))

        if request.POST.get('branch') and request.POST.get('update'):
            # If we have `branch` and `update` then the form was submitted
            return self.do_commit(request, device)
        elif request.POST.get('branch'):
            # If we have `branch` then we can show a diff
            return self.show_diff(request, device)
        else:
            # First ask which branch they want
            return self.ask_branch(request, device)
