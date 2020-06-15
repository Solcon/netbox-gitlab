from django import forms

from dcim.models import Device, Interface
from netbox_gitlab.fields import HTML5RegexField
from utilities.forms import BootstrapMixin


class GitLabCommitForm(BootstrapMixin, forms.Form):
    branch = HTML5RegexField(label='GitLab Branch',
                             regex='[a-z0-9]+([_-][a-z0-9]+)*', min_length=3, max_length=50,
                             help_text='Choose an existing branch or create a new one')
    update = forms.CharField()


class GitLabCommitInventoryForm(GitLabCommitForm):
    pass


class GitLabCommitDeviceForm(GitLabCommitForm):
    pass


class GitLabCommitInterfacesForm(GitLabCommitForm):
    device = forms.ModelChoiceField(queryset=Device.objects.all())
    pk = forms.ModelMultipleChoiceField(queryset=Interface.objects.all())
