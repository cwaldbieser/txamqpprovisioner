=================
txamqpprovisioner
=================

The Twisted AMQP Provisioner (*txamqpprovisioner*) reads group membership
messages from an AMQP message queue and passes them to a back end provisioner
to be acted upon.

There are 2 broad kinds of provisioners.  Membership provisioners reflect group
memberships in their targets.  An example of this kind of provisioner is the 
LDAPProvisioner back end.  Account provisioners create, modify, and remove
accounts in their targets based on the messages they receive.

The Provisioner Delivery Service (Kiki) is a special kind of provisioner that
can accept messages from different kinds of sources, perfrom group and
attribute lookups, compose standard messages, and route them to the intended
provisioners.

The general architecture for this provisioner system looks like a pipline
that flows from event sources to a provisioner delivery service and finally to
the provisioners.  There may be multiple pipelines.  For example, there may be
separate pipelines for membership provisioners and account provisioners.

