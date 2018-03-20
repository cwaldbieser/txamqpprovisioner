
.. _board-effect_provisioner:

========================
Board Effect Provisioner
========================

The Board Effect provisioner is the precursor the
:ref:`REST provisioner <rest_provisioner>`.  As such, many of the options that
generally apply to the REST provisioner apply to this provisioner unless
otherwise noted.

This provisioner syncs accounts and workgroup permissions to the
`Board Effect <https://www.boardeffect.com/>`_ service.  To use this
provisioner, set the *provisioner* option under the APPLICATION section to
**board_effect**.

-------------
Configuration
-------------

Example:

.. code-block:: ini
    :linenos:

    log_level = DEBUG
    diagnostic_mode = 0
    api_key = API-KEY
    endpoint = tls:host=example.boardeffect.com:port=443
    url_prefix = https://example.boardeffect.com/api/v3
    cache_size = 1000
    unmanaged_logins = nonssoadmin
    provision_group = app:board_effect:policies:board_effect
    local_computed_match_template = {{subject}}@example.net
    workroom_map = /etc/txamqpprovisioners/provisioners/board-effect/workroom_map.json
    workroom_cache_size = 100
    workroom_retry_delay = 60
    authenticate = /auth/api_key.json
    accounts_query = /users/
    workrooms_query = /workrooms/
    workroom_members = /workrooms/{{workroom_id}}/users
    workroom_subject = /workrooms/{{workroom_id}}/users/{{subject_id}}

.. note::

    Some lines in this example show lots of curly braces (e.g. lines 9, 16, and
    17).  These values are `Jinja2 <http://jinja.pocoo.org/docs/2.10/>`_ 
    templates.  The keys enclosed in braces will be replaced with the values
    associated with them at runtime.


