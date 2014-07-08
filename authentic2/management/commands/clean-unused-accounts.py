from optparse import make_option
import logging
import datetime

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.core.mail import send_mail
from django.utils.timezone import now
from django.template.loader import render_to_string

from authentic2.models import DeletedUser

from django.conf import settings

def print_table(table):
    col_width = [max(len(x) for x in col) for col in zip(*table)]
    for line in table:
        line = u"| " + u" | ".join(u"{0:>{1}}".format(x, col_width[i])
                                for i, x in enumerate(line)) + u" |"
        print line

class Command(BaseCommand):
    args = '<clean_threshold>'
    help = '''Clean unused accounts'''

    option_list = BaseCommand.option_list + (
            make_option("--alert-thresholds", 
                help='list of durations before sending an alert '
                    'message for unused account, default is none',
                default = None),
            make_option("--period", type='int',
                help='period between two calls to '
                    'clean-unused-accounts as days, default is 1',
                default=1),
            make_option("--fake", action='store_true', help='do nothing',
                default=False),
            make_option("--filter", help='filter to apply to the user queryset, '
                'the Django filter key and value are separated by character =', action='append', default=[]),
            make_option('--from-email', default=settings.DEFAULT_FROM_EMAIL,
                help='sender address for notifications, default is DEFAULT_FROM_EMAIL from settings'),
    )

    def handle(self, *args, **options):
        if len(args) < 1:
            raise CommandError('missing clean_threshold')
        if options['period'] < 1:
            raise CommandError('period must be > 0')
        try:
            clean_threshold = int(args[0])
            if clean_threshold < 1:
                raise ValueError()
        except ValueError:
            raise CommandError('clean_threshold must be an integer > 0')

        if options['verbosity'] == '0':
            logging.basicConfig(level=logging.CRITICAL)
        if options['verbosity'] == '1':
            logging.basicConfig(level=logging.WARNING)
        elif options['verbosity'] == '2':
            logging.basicConfig(level=logging.INFO)
        elif options['verbosity'] == '3':
            logging.basicConfig(level=logging.DEBUG)

        log = logging.getLogger(__name__)
        n = now().replace(hour=0, minute=0, second=0, microsecond=0)
        self.fake = options['fake']
        self.from_email = options['from_email']
        if self.fake:
            log.info('fake call to clean-unused-accounts')
        users = User.objects.all()
        if options['filter']:
            for f in options['filter']:
                key, value = f.split('=', 1)
                try:
                    users = users.filter(**{key: value})
                except:
                    raise CommandError('invalid --filter %s' % f)
        if options['alert_thresholds']:
            alert_thresholds = options['alert_thresholds']
            alert_thresholds = alert_thresholds.split(',')
            try:
                alert_thresholds = map(int, alert_thresholds)
            except ValueError:
                raise CommandError('alert_thresholds must be a comma '
                        'separated list of integers')
            for threshold in alert_thresholds:
                if not (0 < threshold < clean_threshold):
                    raise CommandError('alert-threshold must a positive integer '
                            'inferior to clean-threshold: 0 < %d < %d' % (
                                threshold, clean_threshold))
            for threshold in alert_thresholds:
                a = n - datetime.timedelta(days=threshold)
                b = n - datetime.timedelta(days=threshold-options['period'])
                for user in users.filter(last_login__lt=b, last_login__gte=a):
                    log.info('%s last login %d days ago, sending alert', user, threshold)
                    self.send_alert(user, threshold, clean_threshold-threshold)
        threshold = n - datetime.timedelta(days=clean_threshold)
        for user in users.filter(last_login__lt=threshold):
            d = n - user.last_login
            log.info('%s last login %d days ago, deleting user', user, d.days)
            self.delete_user(user, clean_threshold)


    def send_alert(self, user, threshold, clean_threshold):
        ctx = { 'user': user, 'threshold': threshold,
                'clean_threshold': clean_threshold }
        self.send_mail('authentic2/unused_account_alert', user, ctx)


    def send_mail(self, prefix, user, ctx):
        log = logging.getLogger(__name__)

        if not user.email:
            log.debug('%s has no email, no mail sent', user)
        subject = render_to_string(prefix + '_subject.txt', ctx).strip()
        body = render_to_string(prefix + '_body.txt', ctx)
        if not self.fake:
            try:
                log.debug('sending mail to %s', user.email)
                send_mail(subject, body, self.from_email, [user.email])
            except:
                log.exception('email sending failure')


    def delete_user(self, user, threshold):
        ctx = { 'user': user, 'threshold': threshold }
        self.send_mail('authentic2/unused_account_delete', user,
                ctx)
        if not self.fake:
            DeletedUser.objects.delete_user(user)
