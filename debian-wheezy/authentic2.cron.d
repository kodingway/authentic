PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

0 * * * * authentic authentic2-ctl clearsessions
5 * * * * authentic authentic2-ctl cleanupauthentic
10 * * * * authentic authentic2-ctl sync-ldap-users

