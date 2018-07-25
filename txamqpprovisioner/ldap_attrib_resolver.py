
from __future__ import print_function
import jinja2
from ldap_utils import escape_filter_chars
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient, ldapsyntax
from ldaptor.protocols.ldap.distinguishedname import DistinguishedName, RelativeDistinguishedName
from ldaptor.protocols.ldap.distinguishedname import unescape as unescapeDN
from ldaptor.protocols.ldap import ldaperrors
from twisted.internet import endpoints
from twisted.internet.defer import (
    inlineCallbacks, 
    returnValue,
)
from twisted.plugin import IPlugin
from zope.interface import implements
from interface import (
    IAttributeResolverFactory,
    IAttributeResolver,
)

def require_option(cp, section, option):
    """
    Require an option or raise an exception.
    """
    if not cp.has_option(section, option):
        raise Exception(
            "Option `{section}::{option}` is required.".format(
            section=section,
            option=option))


class LDAPAttributeResolverFactory(object):
    implements(IPlugin, IAttributeResolverFactory)
    tag = "ldap_attrib_resolver"

    def generate_attribute_resolver(self, config_parser):
        """
        Create an object that implements IAttributeResolver.
        """
        resolver = LDAPAttributeResolver()
        section = "LDAP Attribute Resolver"
        if not config_parser.has_section(section):
            raise Exception(
                "Missing config section '{0}'.".format(
                section))
        options = config_parser.options(section)
        for name, prop in [
            ('endpoint', 'endpoint_s'),
            ('base_dn', 'base_dn'),
            ('bind_dn', 'bind_dn'),
            ('bind_passwd', 'bind_passwd')]:
            require_option(config_parser, section, name) 
            value = config_parser.get(section, name)
            setattr(resolver, prop, value)
        require_option(config_parser, section, "start_tls") 
        start_tls = config_parser.getboolean(section, "start_tls")
        resolver.start_tls = start_tls
        require_option(config_parser, section, "attributes") 
        attribs = config_parser.get(section, "attributes")
        resolver.attributes = attribs.strip().split()
        resolver.template_env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True)
        resolver.template_env.filters['escape_filter_chars'] = escape_filter_chars
        filter_template = config_parser.get(section, "filter")
        resolver.filter_template = resolver.template_env.from_string(
            filter_template)
        return resolver


class LDAPAttributeResolver(object):
    implements(IAttributeResolver)
    log = None
    endpoint_s = None
    base_dn = None
    bind_dn = None
    bind_passwd = None
    start_tls = True
    reactor = None
    attributes = None
    template_env = None
    filter_template = None
    ldap_conn_timeout = 30
    client_ = None
    client_unbind_id_ = None

    @inlineCallbacks
    def resolve_attributes(self, subject):
        """
        Return a Deferred that fires with the attributes for a subject.
        Atributes are a mapping of keys to a list of values.
        """
        log = self.log
        attribs = {}
        # Connect and BIND to a directory.
        client = yield self.get_ldap_client() 
        # Search for a subject.
        attributes = self.attributes
        base_dn = self.base_dn
        o = ldapsyntax.LDAPEntry(client, base_dn)
        fltr = self.filter_template.render(subject=subject)
        log.debug("LDAP fltr: {fltr}", fltr=fltr)
        try:
            results = yield o.search(filterText=fltr, attributes=attributes)
        except Exception as ex:
            self.log.error(
                "Error while searching for LDAP subject {subject}", 
                event_type='error_load_ldap_subject',
                subject=subject) 
            raise
        finally:
            self.release_ldap_client_()
            log.debug("{classname}: Scheduled LDAP client for release.", classname=self.__class__.__name__)
        for n, entry in enumerate(results):
            if n != 0:
                raise Exception(
                    "Multiple entries received for subject `{subject}`.".format(
                    subject=subject))
            # Collect the values for the relevant attributes.
            for name in attributes:
                value = entry.get(name, None)
                if value is not None: 
                    attribs[name] = list(value)
        returnValue(attribs)        

    @inlineCallbacks
    def get_ldap_client(self):
        """
        Returns a Deferred that fires with an asynchronous LDAP client.
        """
        log = self.log
        log.debug("{classname}: Entered `get_ldap_client()`. self.id == {instance_id}", classname=self.__class__.__name__, instance_id=id(self))
        client = self.client_
        if not client is None:
            self.clear_scheduled_unbind_()
            log.debug("{classname}: Cleared scheduled UNBIND; returning existing LDAP client.", classname=self.__class__.__name__)
            returnValue(client)
        start_tls = self.start_tls
        endpoint_s = self.endpoint_s
        bind_dn = self.bind_dn
        bind_passwd = self.bind_passwd
        reactor = self.reactor
        ep = endpoints.clientFromString(reactor, endpoint_s)
        log.debug("LDAP endpoint: {endpoint}", endpoint=endpoint_s)
        client = yield endpoints.connectProtocol(ep, ldapclient.LDAPClient())
        self.client_ = client
        log.debug("Client connection established to LDAP endpoint.")
        try:
            if start_tls:
                yield client.startTLS()
                log.debug("{classname}: LDAP client initiated StartTLS.", event_type='ldap_starttls', classname=self.__class__.__name__)
            if bind_dn and bind_passwd:
                yield client.bind(bind_dn, bind_passwd)
                log.debug(
                    "LDAP client BIND as '{bind_dn}'.",
                    event_type='ldap_bind',
                    bind_dn=bind_dn)
        except Exception:
            self.unbind_client_()
            raise
        self.clear_scheduled_unbind_()
        log.debug("'{classname}': Returning new LDAP client.", classname=self.__class__.__name__)
        returnValue(client)

    def clear_scheduled_unbind_(self):
        client_unbind_id = self.client_unbind_id_
        if client_unbind_id is not None:
            client_unbind_id.cancel()
            self.client_unbind_id_ = None

    def release_ldap_client_(self):
        """
        Schedule LDAP client to be released if it is not used again within the timeout period.
        """
        self.clear_scheduled_unbind_()
        ldap_conn_timeout = self.ldap_conn_timeout
        reactor = self.reactor
        self.client_unbind_id_ = reactor.callLater(ldap_conn_timeout, self.unbind_client_)
       
    def unbind_client_(self):
        log = self.log
        client = self.client_
        self.client_unbind_id_ = None
        self.client_ = None
        if client is None:
            return
        if client.connected:
            client.unbind() 
            log.debug("'{classname}' LDAP client disconnected.", classname=self.__class__.__name__)
