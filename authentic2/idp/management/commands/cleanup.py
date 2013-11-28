import warnings

from authentic2.idp.management.commands import cleanupauthentic


class Command(cleanupauthentic.Command):
    def handle_noargs(self, **options):
        warnings.warn(
            "The `cleanup` command has been deprecated in favor of `cleanupauthentic`.",
            PendingDeprecationWarning)
        super(Command, self).handle_noargs(**options)
