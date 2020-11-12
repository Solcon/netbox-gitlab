from django.forms import RegexField


class HTML5RegexField(RegexField):
    def __init__(self, regex, **kwargs):
        super().__init__(regex, **kwargs)

        # Reapply attrs
        extra_attrs = self.widget_attrs(self.widget)
        if extra_attrs:
            self.widget.attrs.update(extra_attrs)

    def widget_attrs(self, widget):
        attrs = super().widget_attrs(widget)
        if hasattr(self, '_regex'):
            attrs['pattern'] = self._regex.pattern
        return attrs


class BranchNameField(HTML5RegexField):
    def __init__(self, **kwargs):
        params = {
            'label': 'GitLab Branch',
            'regex': '[a-z0-9]+([_-][a-z0-9]+)*',
            'min_length': 3,
            'max_length': 50,
            'help_text': 'Choose an existing branch or create a new one'
        }
        params.update(**kwargs)
        super().__init__(**params)
