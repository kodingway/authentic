.. _administration_with_policies:

==================
Work with policies
==================

The policy management with global policies is nearly used for any kind of
policy in Authentic 2.

For each kind of these policies, the system takes in account two special
global policies named 'Default' and 'All':

* There is always a system default that does not correspond to the 'Default'
  policy. This is used to make Authentic 2 boot without initial
  configuration. When you add a 'Default' policy, the system default are not
  used anymore.
* A policy has always a name, 'Default' and 'All' are the names of two special
  policies with their name hardcoded. But you can create or delete them.
* If no other policy applies, the policy 'Default' applies.
* A policy can be created and attached to any related object. This policy is
  authoritative on the policy 'Default'.
* If the policy 'All' exists, it is authoritative on any other policy.
* The global policies 'All' and 'Default' are created by the administrator if
  necessary.
* A policy is taken in account only if it is enabled.
* When a regular policy is associated with an object, it is taken in account
  only if the option 'enable the following policy' is checked on the oject.

It is advised to add a 'Default' global policy when it is expected to apply a
policy to all related objects. A 'Default' global policy should be defined to
avoid misonfiguration.

Add a regular policy to some objects are used to handle particular
configurations for a subset of related objects.

An 'All' global policy should be used to enforce a global configuration for
all related objects or for testing purposes.
