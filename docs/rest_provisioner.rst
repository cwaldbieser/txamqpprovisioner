
.. _rest_provisioner:

=================
REST Provisioners
=================

REST provisioners are a class of provisioner that derive from the base
:py:class:`txamqpprovisioner.rest_provisioner.RestProvisioner`.  These
provisioners share many similar traits and options.

Each REST provisioner uses an HTTP-based API in order to query and manipulate
a target system.  Many APIs claim to be RESTful, though strictly speaking this
is not a requirement.

* **account_cache_size** (default 1000) - The provisioner caches the remote
  API ID of accounts and can retreive them by the local subject ID.  The map
  it uses to cache this information is limited in size.  If an API ID not in
  the cache is required, the provisioner needs to make an API call to retreive
  it.  The cache is a LRU cache.
* **account_sync_rate_limit_ms** (default 0) - Reconcilliation of local subjects
  to target accounts typically involves multiple API calls.  Some services limit
  the rate at which API calls may be issued.  This time in milliseconds limits
  the rate at which API calls are issued during account reconcillation.
* **account_cache_validity_period** (default 0) - Some provisioners are able to
  pre-fill the account cache.  If a provisioner pre-fills the cache, this setting
  represents the length of time in seconds that the cache should be absolutely
  trusted to contain accurate information.  I.e. if the cache is queried for a
  subject, and the subject is not in the cache, the remote system should not be
  queried.  It should be assumed the cache is accurate and the subject does not
  exist in the remote system.  This is an optimization setting that can prevent
  a provisioner from making costly remote lookups for accounts that are unlikely
  to exist.
* **client_secret** - Many services require some kind of shared secret that must
  be presented by the client before an API call will be honored.  This may be a
  password, a long-lived token that can be used to obtain short-lived authorization
  tokens, etc.  The exact format and usage of the secret is dependent on the 
  service.
* **endpoint** - See A `Twisted endpoint <https://twistedmatrix.com/documents/current/core/howto/endpoints.html>`_.
  Basically, a connection-string like description of a host, port, and various
  other options for a network service.  In many cases, the endpoint will simply
  match the host and port parts of a URL specified in the *url_prefix* setting.
* **group_sync_strategy** ("add-member-first": default, "query-first") - When
  synchronizing local memberships to target system memberships, the default
  strategy is to attempt to add members to the remote group whether they are
  already members on the remote side or not.  The full membership of the remote
  group is then queried and members that do not belong are removed.
  Some services will produce an error if a member is added to a group to which
  it already is a member.  For such services, the "query-first" strategy
  determines if each local member is already a member of the remote group (via
  API calls) before adding the member to the group. 
* **member_sync_rate_limit_ms** (default 0) - As per *account_sync_rate_limit_ms*,
  but in this case for group membership reconcilliations.
* **provision_group** - If this option is set, then messages delivered to the
  provisioner that have this group as the target signal that the provisioner
  should provision / enable / reenable the account on the target service.
* **provision_strategy** ("query-first": default, "create-first") - When provisioning
  a remote account on the target system, the default is to query if the account
  already exists using an API call.  If it does, the account is updated rather than
  created.  The "create-first" strategy attempts to create the account via an API
  call without first checking if it exists on the remote end.  If this produces
  an error, only then will an API call be used to query the account and update
  it.
* **target_group_cache_size** (default 100) - The provisioner caches the API IDs
  of groups on the remote system.  If an API call the provisioner makes requires
  a group API ID and it is not in the cache, the provisioner will need to query
  for the ID first.  The cache is a LRU cache.
* **target_group_map** - Maps the groups sent in messages to a queryable group
  name on the target system.  A simple JSON mapping.
* **target_group_retry_delay** (default 20s) - Because of the asynchronous nature
  of provisioners, it may be possible that a request to add a member to a group
  precedes a request to provision the member on the remote system.  To compensate
  for this, if an API ID for the remote account cannot be obtained in order to
  make it a member of a remote group, the request will be delayed for the number
  of seconds specified in this setting.  The provisioner will then try to obtain
  the API ID of the remote account again.  If it fails a second time, the request
  will be discarded.  Otherwise the request will procede as normal.
* **unmanaged_logins** - A space-separated list of :term:`match values` for
  accounts that may or may not exist in the target system.  The provisioner will
  not attempt to manage these accounts on the target.  This is useful for
  preventing emergency accounts or system accounts from being managed by the
  provisioning infrastructure.
* **url_prefix** - A prefix applied to all API URLs.  
