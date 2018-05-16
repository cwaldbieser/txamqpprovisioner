
====================================
Active Directory Account Provisioner
====================================

-------------------------
Provisioner Configuration
-------------------------

To use the :py:class:`ADAccountProvisioner` backend, set the provisioner option
under the APPLICATION section to **ad_account_provisioner**.

The :py:class:`ADAccountProvisioner` service treats the Active Directory DIT as
a target system.  It can provision or deprovision accounts in the DIT under a
single OU container.  Deprovisioning simply disables accounts rather than
deleting entries.

The options for the AD account provisioner are:

* **log_level** (optional) - This option can override the global log level for 
  events logged by this service.
* **provision_group** - A fully qualified group name that must match the group
  in the message being processed.  If the group does not match, the provisioner
  will log the message and discard it.
* **endpoint** - The `Twisted client endpoint <https://twistedmatrix.com/documents/current/core/howto/endpoints.html#clients>`_
  used to connect to the Active Directory LDAP service.
* **use_starttls** (optional) - 1 = use StartTLS, 0 = no StartTLS; default 1 (use StartTLS).
* **starttls_hostname** - If using StartTLS, the hostname that the LDAP client
  should expect to find in the Active Directory x509 certificate subject or 
  subject alternative name field.
* **starttls_trust_anchor** - A file in PEM format that contains the x509
  certificate authorities that the LDAP client should trust when using StartTLS.
* **bind_dn** - The DN used to BIND to Active Directory via LDAP.  This DN must
  have sufficient rights to create and disable entries in the *base_dn* container.
* **bind_passwd** - The password for the *bind_dn*.
* **base_dn** - The DN of the OU container in which the provisioner will search
  for, create, and disable user accounts.
* **filter** - An LDAP filter used to select user entries.  Entries not matching
  the filter will not be considered by the provisioner.
* **account_template** - The path to a `jinja2 <http://jinja.pocoo.org/>`_ template
  that will be used to create a JSON representation of the account to be created.

"""""""
Example
"""""""

.. code-block:: ini

    log_level = DEBUG
    provision_group = app:ad:exports:ad
    endpoint = tcp:host=dc0.ad.example.net:port=389
    use_starttls = 1
    starttls_hostname = dc0.ad.example.net
    starttls_trust_anchor = /etc/txamqpprovisioners/tls/ca/cacert.cert.pem
    bind_dn = CN=Service Account,OU=Service Accounts,DC=ad,DC=example,DC=net
    bind_passwd = SECRET_DONT_TELL
    base_dn = OU=People,DC=ad,DC=example,DC=net
    filter = (objectClass=user)
    account_template = /etc/txamqpprovisioners/provisioners/ad/ad-accounts-template.jinja2

------------------------------
Account Template Configuration
------------------------------

The account template should render to a JSON mapping of attribute names to
lists of attribute values.  Only attributes which exist in your 
Active Directory's schema can be created for new entries.

The filter `equote` is available to escape values used in JSON quoted strings.
The name `attributes` resolves to a mapping of attributes for the subject that
were provided in the message.
The name `subject` is available and resolves to the subject ID from the message.

Example:

.. code-block:: JSON

    {
        "dn": "CN={{attributes.uid[0]|equote}},OU=People,DC=ad,DC=example,DC=net",
        "cn": ["{{attributes.uid[0]|equote}}"],
        "displayName": ["{{attributes.givenName[0]|equote}} {{attributes.sn[0]|equote}}"],
        "distinguishedName": ["CN={{attributes.uid[0]|equote}},OU=People,DC=ad,DC=example,DC=net"],
        "givenName": ["{{attributes.givenName[0]|equote}}"],
        "name": ["{{attributes.givenName[0]|equote}} {{attributes.sn[0]|equote}}"],
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "sAMAccountName": ["{{attributes.uid[0]|equote}}"],
        "sn": ["{{attributes.sn[0]|equote}}"],
        "userPrincipalName": ["{{attributes.uid[0]|equote}}@ad.example.net"],
        "userAccountControl": [544]
    }

.. warning::

    Make sure that your template maps attribute names to **lists** of attribute
    values.  Even if there is only a single value.

