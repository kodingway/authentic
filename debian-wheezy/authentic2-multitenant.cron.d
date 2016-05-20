PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 * * * * authentic authentic2-multitenant-manage tenant_command clearsessions --all-tenants
5 * * * * authentic authentic2-multitenant-manage tenant_command cleanupauthentic --all-tenants
10 * * * * authentic authentic2-multitenant-manage tenant_command sync-ldap-users --all-tenants
