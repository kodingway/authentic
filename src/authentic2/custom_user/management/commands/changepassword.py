from __future__ import unicode_literals

import getpass
from optparse import make_option

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import DEFAULT_DB_ALIAS
from django.utils.encoding import force_str
from django.db.models.query import Q
from django.core.exceptions import MultipleObjectsReturned


class Command(BaseCommand):
    option_list = BaseCommand.option_list + (
        make_option('--database', action='store', dest='database',
            default=DEFAULT_DB_ALIAS, help='Specifies the database to use. Default is "default".'),
    )
    help = "Change a user's password for django.contrib.auth."

    requires_system_checks = False

    def _get_pass(self, prompt="Password: "):
        p = getpass.getpass(prompt=force_str(prompt))
        if not p:
            raise CommandError("aborted")
        return p

    def handle(self, *args, **options):
        if len(args) > 1:
            raise CommandError("need exactly one or zero arguments for username")

        if args:
            username, = args
        else:
            username = getpass.getuser()

        UserModel = get_user_model()

        qs = UserModel._default_manager.using(options.get('database'))
        qs = qs.filter(Q(uuid=username)|Q(username=username)|Q(email=username))
        try:
            u = qs.get()
        except UserModel.DoesNotExist:
            raise CommandError("user '%s' does not exist" % username)
        except MultipleObjectsReturned:
            while True:
                print 'Select an user:'
                for i, user in enumerate(qs):
                    print '%d.' % (i+1), user
                print '> ',
                try:
                    j = input()
                except SyntaxError:
                    print 'Please enter an integer'
                    continue
                if not isinstance(uid, int):
                    print 'Please enter an integer'
                    continue
                try:
                    u = qs[j-1]
                    break
                except IndexError:
                    print 'Please enter an integer between 1 and %d' % qs.count()
                    continue

        self.stdout.write("Changing password for user '%s'\n" % u)

        MAX_TRIES = 3
        count = 0
        p1, p2 = 1, 2  # To make them initially mismatch.
        while p1 != p2 and count < MAX_TRIES:
            p1 = self._get_pass()
            p2 = self._get_pass("Password (again): ")
            if p1 != p2:
                self.stdout.write("Passwords do not match. Please try again.\n")
                count = count + 1

        if count == MAX_TRIES:
            raise CommandError("Aborting password change for user '%s' after %s attempts" % (u, count))

        u.set_password(p1)
        u.save()

        return "Password changed successfully for user '%s'" % u
