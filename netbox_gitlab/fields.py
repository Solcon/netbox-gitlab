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
