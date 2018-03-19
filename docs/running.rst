
=======
Running
=======

------------------------------------
Running from a cloned git repository
------------------------------------

A single instance of a provisioner may be invoked as a twisted plugin:

.. code:: shell

    $ cd /project/folder
    $ export PYTHONPATH=.
    $ twistd -n provisioner

-------------------------------
Running from installed software
-------------------------------

.. warning::

    The author hasn't gotten around to writing proper Python install scripts
    as of yet.  Once he does, the recommended way to install the software will
    be with `pip`.  Once that happens, you won't need to worry about your 
    current working folder or your PYTHONPATH.

.. code:: shell

    $ twistd -n provisioner

Other options for the `provisioner` plugin or the `twistd` program itself
are available.  Notably, the `-n` option used in the above commands runs 
the program in the foreground.  See the `OS Service Integration examples`_ 
for an example of additional options being used.  Also, use the `--help` 
option for more information.

.. note::

    In the architecture for the txamqpprovisioner system an AMQP message
    exchange forms a backbone that connects event sources to provisioners.
    As such, there isn't a single `run` command for the entire system.
    Instead, individual services can be stopped and started.

-------------------------------
OS Service Integration examples
-------------------------------

"""""""""""""
RHEL6 Upstart
"""""""""""""

The following is an example of a simple `Upstart <http://upstart.ubuntu.com/>`_
script to daemonize an LDAP subject provisioner service.

.. code-block:: shell
    :linenos:

    description "Twisted LDAP Subject Provisioner"
    author "Carl <waldbiec@lafayette.edu>"

    start on runlevel [2345]
    stop on runlevel [016]

    kill timeout 60
    respawn
    respawn limit 10 5
     
    script
    /usr/bin/sudo -u grouper /bin/bash <<START
    cd /opt/txamqpprovisioner/ 
    . ./pyenv/bin/activate 
    export LD_LIBRARY_PATH=/usr/local/lib64
    export PYTHONPATH=.
    twistd -n --syslog --prefix ldapsubj --pidfile /var/run/txamqpprovisioner/ldapsubj.pid  provisioner -c /etc/grouper/provisioners/ldapsubj.cfg
    START
    end script

The majority of the configuration is the Upstart boilerplate.  The actual
script block is a shell HERE document from lines 13-16.  The script is
run as the *grouper* user on the system using the :program:`sudo` command.

On line 13, the current directory is changed to the software installation
folder.  On line 14, the Python virtual environment for the software is
activated.  Line 15 sets up an environment variable- in this case the
:envvar:`LD_LIBRARY_PATH` variable lets the operating system know that it needs
to look in a non-standard location for a shared library the software depends
on.

Line 16 is where the service is finally invoked.  In this case, the `-n`
option is used to run the service in the foreground.  The Upstart machinery will
take care of running the process as a background service.  Other options are
provided to log to syslog using a particular prefix, choose a file to use for
tracking the process PID, and specifying an individual configuration file.

