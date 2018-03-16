========
Glossary
========

.. glossary::

    Directory Information Tree
    DIT
        A tree-like structure an LDAP service uses to represent information to
        LDAP clients.  At the root of the tree is a single node that may have
        one or more child nodes.  Each child may have one or more children.
        The type of the node will determine whether or not the node may be a
        container for other nodes (i.e. whether the node may have children).

    Provisioner Delivery Service
    PDS 
        Provisioner Delivery Service.  A component that reads raw messages 
        from event sources.  It repackages the message, adding addtional
        data from other sources, and applies routing labels before delivering
        the new message to an exchange.

        The tag name for the PDS is "kiki", named after the children's movie
        *Kiki's Delivery Service* (1989).

    match values
        Match values can be computed for local subjects or remote accounts.  The
        algorithms for producing a match value on the local and remote sides may
        be different.  A match value on the local side that is identical to a
        match value on the remote side means that the remote account is a
        projection of the local account in the target system.


