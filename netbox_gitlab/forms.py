from django import forms

from dcim.models import Interface
from netbox_gitlab.fields import BranchNameField
from utilities.forms import BootstrapMixin


class GitLabBranchForm(BootstrapMixin, forms.Form):
    branch = BranchNameField()


class GitLabCommitInventoryForm(BootstrapMixin, forms.Form):
    branch = BranchNameField()
    update = forms.CharField()


class GitLabCommitDeviceForm(BootstrapMixin, forms.Form):
    branch = BranchNameField()
    update = forms.CharField()


class GitLabBranchInterfacesForm(BootstrapMixin, forms.Form):
    pk = forms.ModelMultipleChoiceField(queryset=Interface.objects.all(), required=False)

    branch = BranchNameField()


class GitLabCommitInterfacesForm(BootstrapMixin, forms.Form):
    pk = forms.ModelMultipleChoiceField(queryset=Interface.objects.all(), required=False)

    branch = BranchNameField()
    update = forms.CharField()
