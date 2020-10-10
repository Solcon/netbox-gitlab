from django.db import models
from django.utils.translation import gettext_lazy as _

from circuits.models import CircuitTermination
from dcim.models import Cable, FrontPort, Interface, RearPort


class PermissionSupport(models.Model):
    class Meta:
        # No database table creation or deletion operations will be performed for this model.
        managed = False

        permissions = (
            ('export_device', 'Can export device to GitLab'),
            ('export_interface', 'Can export interface to GitLab'),
        )


class TraceElementQuerySet(models.QuerySet):
    def _filter_or_exclude(self, negate, *args, **kwargs):
        # Handle filtering on element
        if 'element' in kwargs:
            element = kwargs.pop('element')
            if element is None:
                kwargs['_cable'] = None
                kwargs['_interface'] = None
                kwargs['_front_port'] = None
                kwargs['_rear_port'] = None
                kwargs['_circuit_termination'] = None
            elif isinstance(element, Cable):
                kwargs['_cable'] = element
            elif isinstance(element, Interface):
                kwargs['_interface'] = element
            elif isinstance(element, FrontPort):
                kwargs['_front_port'] = element
            elif isinstance(element, RearPort):
                kwargs['_rear_port'] = element
            elif isinstance(element, CircuitTermination):
                kwargs['_circuit_termination'] = element
            else:
                raise ValueError("unsupported element type")

        return super()._filter_or_exclude(negate, *args, **kwargs)


class TraceElement(models.Model):
    from_interface = models.ForeignKey(
        verbose_name=_('from interface'),
        to=Interface,
        on_delete=models.CASCADE,
        related_name='trace_elements',
    )
    step = models.PositiveIntegerField(
        verbose_name=_('step'),
    )

    _cable = models.ForeignKey(
        to=Cable,
        on_delete=models.CASCADE,
        related_name='+',
        blank=True,
        null=True,
    )
    _interface = models.ForeignKey(
        to=Interface,
        on_delete=models.CASCADE,
        related_name='+',
        blank=True,
        null=True,
    )
    _front_port = models.ForeignKey(
        to=FrontPort,
        on_delete=models.CASCADE,
        related_name='+',
        blank=True,
        null=True,
    )
    _rear_port = models.ForeignKey(
        to=RearPort,
        on_delete=models.CASCADE,
        related_name='+',
        blank=True,
        null=True,
    )
    _circuit_termination = models.ForeignKey(
        to=CircuitTermination,
        on_delete=models.CASCADE,
        related_name='+',
        blank=True,
        null=True,
    )

    objects = TraceElementQuerySet.as_manager()

    class Meta:
        ordering = ('from_interface_id', 'step')
        unique_together = [
            ('from_interface', 'step'),
        ]
        verbose_name = _('trace element')
        verbose_name_plural = _('trace elements')

    def __str__(self):
        return f"{self.from_interface}[{self.step}]: {self.element}"

    @property
    def element_type(self):
        if self._cable_id:
            return 'cable'
        elif self._interface_id:
            return 'interface'
        elif self._front_port_id:
            return 'front_port'
        elif self._rear_port_id:
            return 'rear_port'
        elif self._circuit_termination_id:
            return 'circuit_termination'
        else:
            return None

    @property
    def element(self):
        if self._cable_id:
            return self._cable
        elif self._interface_id:
            return self._interface
        elif self._front_port_id:
            return self._front_port
        elif self._rear_port_id:
            return self._rear_port
        elif self._circuit_termination_id:
            return self._circuit_termination
        else:
            return None

    @element.setter
    def element(self, value):
        self._cable = None
        self._interface = None
        self._front_port = None
        self._rear_port = None
        self._circuit_termination = None

        if isinstance(value, Cable):
            self._cable = value
        elif isinstance(value, Interface):
            self._interface = value
        elif isinstance(value, FrontPort):
            self._front_port = value
        elif isinstance(value, RearPort):
            self._rear_port = value
        elif isinstance(value, CircuitTermination):
            self._circuit_termination = value
