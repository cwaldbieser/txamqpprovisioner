
===============
SSH Provisioner
===============

-------------------------
Provisioner Configuration
-------------------------

To use the :py:class:`SSHProvisioner` backend, set the provisioner option under
the APPLICATION section to **ssh**.

The :py:class:`SSHProvisioner` service uses the SSH protocol to establish a
secure connection to a remote host that runs an SSH service.  The provisioner
invokes an arbitrary command on the remote host and may pass it command line
arguments or data on standard input.  Commands for provisioning, deprovisioning,
and reconcilliation are configured separately.  All commands are configured as
inline `jinja2`_ templates.  They are passed both the subject (as "subject") and
the mapped group name (as "group").  See :ref:`group mapping <group-map-config>` 
details, below.

Templates will have the `shellquote` filter available to them to perform
Bourne Shell style escaping on values.

Commands may either be configured as "simple" or "input" commands.  Simple
commands are expected to run using only command line arguments.
 
The options for the SSH provisioner are:

* **log_level** (optional) - This option can override the global log level for 
  events logged by this service.
* **user** - The user name used to log into the remote host.
* **host** - The remote host.
* **port** (optional) - The port to connect to on the remote host (default 22).
* **keys** - Path to the SSH private key used to authenticate to the remote host.
* **provision_cmd** - A template for a command to provision an individual subject. 
* **provision_cmd_type** - "simple" or "input"
* **provision_input** - A template applied to subject/group.  The result is written
  to the STDIN of the *provision_cmd*.
* **deprovision_cmd** - A template for a command to deprovision an individual subject.
* **sync_cmd** - A template for a command to reconcile all subjects for a group.
* **sync_cmd_type** - "simple" or "input"
* **sync_input** - A template applied to subject/group.  The result is written
  to the STDIN of the *sync_cmd*.
* **provision_ok_result** - The expected successful exit code for the *provision_cmd*.
* **deprovision_ok_result** - The expected successful exit code for the *deprovision_cmd*.
* **sync_ok_result** - The expected successful exit code for the *sync_cmd*.
* **group_map** - Path to the group mapping configuration.

"""""""
Example
"""""""

.. code-block:: ini

    [PROVISIONER]
    log_level = DEBUG
    user = provisioner
    host = mailman.example.net
    port = 22
    keys = /home/clientuser/.ssh/id_rsa
    provision_cmd = /usr/bin/sudo /usr/lib/mailman/bin/add_members -r - {{ group |shellquote }}
    provision_cmd_type = input
    provision_input = {{ subject }}@lafayette.edu
    deprovision_cmd = /usr/bin/sudo /usr/lib/mailman/bin/remove_members {{group |shellquote}} {{ subject + "@example.net" |shellquote}}
    sync_cmd = /usr/bin/sudo /usr/lib/mailman/bin/sync_members -f - {{ group |shellquote }}
    sync_cmd_type = input
    sync_input = {{ subject + "@example.net" |newline }}
    provision_ok_result = 0
    deprovision_ok_result = 0
    sync_ok_result = 0
    group_map = /etc/txamqpprovisioners/provisioners/maillists/groupmap.json

.. _group-map-config:

-----------------------
Group Map Configuration
-----------------------

The group map is a JSON file consisting of a sequence of regular expressions that
are each tested against the fully qualified group of the message.  If a pattern
matches the group, the match expressions are passed to a `jinja2`_ template along
with the original group name (under the key "orig_group").  The template is
used to create the group name that is passed to the remote shell command. 

Example:

.. code-block:: json

    [
        ["(?P<stem>app:mailman:exports:)(?P<group>.+)", "{{ group|lower }}"],
        ["(?P<stem>app:hr_maillists:exports:)(?P<group>.+)", "{{ group|lower }}"],
        [".*", ""]
    ]

.. warning::

    If no pattern matches the group, an exception will be thrown and the
    message will not be processed.  In order to ignore a message with an
    unhandled group, it is useful to have a "catch-all" pattern as the last
    rule and map it to some value that the remote command will understand as
    a sentinal value.


.. _jinja2: http://jinja.pocoo.org/

