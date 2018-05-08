
from __future__ import print_function
import datetime
import json
import commentjson
import jinja2 
from textwrap import dedent
import traceback
import attr
from ldap_utils import escape_filter_chars, normalize_dn
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient, ldapsyntax
from ldaptor.protocols.ldap.distinguishedname import DistinguishedName, RelativeDistinguishedName
from ldaptor.protocols.ldap.distinguishedname import unescape as unescapeDN
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols import (
    pureber,
    pureldap
)
from six import iteritems
from twisted.internet import defer, task
from twisted.internet.defer import (
    inlineCallbacks, 
    returnValue,
)
from twisted.internet.endpoints import clientFromString, connectProtocol
from twisted.logger import Logger
from twisted.plugin import IPlugin
from zope.interface import implements, implementer
from config import load_config, section2dict
import constants
from errors import (
    OptionMissingError,
)
from interface import (
    IProvisionerFactory,
    IProvisioner,
)
from utils import get_plugin_factory

def escape_quote(s):
    """
    Escape quotes for use in JSON strings.
    """
    return s.replace('"', r'\"')


@attr.attrs
class ParsedSubjectMessage(object):
    action = attr.attrib()
    group = attr.attrib()
    subject = attr.attrib()
    attributes = attr.attrib(default=attr.Factory(dict))


@attr.attrs
class ParsedSyncMessage(object):
    action = attr.attrib()
    group = attr.attrib()
    subjects = attr.attrib(default=attr.Factory(list))
    attributes = attr.attrib(default=attr.Factory(dict))


class LDAPClientManager(object):
    """
    Manage an LDAP client and unbind when done with the
    connection.

    If the `active` flag is False, don't unbind.  This is useful when you are
    using an existing client and don't want to inject a bunch of conditional
    logic into your code.
    """
    active = False
    client_ = None
    def __init__(self, client, active=True):
        self.client_ = client
        self.active = active

    def __enter__(self):
        return self.client_

    def __exit__(self, ex_type, ex_value, tb):
        if self.active:
            self.client_.unbind()
        return True

        
class ADAccountProvisionerFactory(object):
    implements(IPlugin, IProvisionerFactory)
    tag = "override_this_tag"
    opt_help = "AD Account Provisioner"
    opt_usage = "This plugin does not support any options."

    def generateProvisioner(self, argstring=""):
        """
        Create an object that implements IProvisioner
        """
        provisioner = ADAccountProvisioner()
        return provisioner


class ADAccountProvisioner(object):
    implements(IProvisioner)
    service_state = None
    reactor = None
    log = None
    bind_dn = None
    bind_passwd = None
    base_dn = None
    search_filter = None
    account_template_path = None
    account_template_ = None

    def load_config(self, config_file, default_log_level, logObserverFactory):
        """                                                             
        Load the configuration for this provisioner and initialize it.  
        """             
        log = Logger(observer=logObserverFactory("ERROR"))
        try:
            # Load config.
            scp = load_config(config_file, defaults=self.get_config_defaults())
            section = "PROVISIONER"
            config = section2dict(scp, section)
            self.config = config
            # Start logger.
            log_level = config.get('log_level', default_log_level)
            log = Logger(observer=logObserverFactory(log_level))
            self.log = log
            log.info("Initializing provisioner.",
                event_type='init_provisioner')
            # Load configuration info-- endpoint info, credentials, base DN, etc.
            try:
                self.provision_group = config["provision_group"].lower()
                self.endpoint_s = config["endpoint"]
                self.bind_dn = config["bind_dn"]
                self.bind_passwd = config["bind_passwd"]
                self.base_dn = config["base_dn"]
                self.search_filter = config.get('filter', None)
                self.account_template_path = config["account_template"]
            except KeyError as ex:
                raise OptionMissingError(
                    "A required option was missing: '{}:{}'.".format(
                        section, ex.args[0]))
            self.parse_account_template_()
        except Exception as ex:
            d = self.reactor.callLater(0, self.reactor.stop)
            log.failure("Provisioner failed to initialize: {}".format(ex))
            raise
        return defer.succeed(None)

    def parse_account_template_(self):
        """
        Parse the account template.
        """
        jinja2_env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True)
        jinja2_env.filters['equote'] = escape_quote
        account_template_path = self.account_template_path
        with open(self.account_template_path, "r") as f:
            self.account_template_ = jinja2_env.from_string(f.read())

    @inlineCallbacks                                                   
    def provision(self, amqp_message):             
        """                                                
        Provision an entry based on an AMQP message.  
        """                                              
        log = self.log
        try:
            msg = self.parse_message(amqp_message)
            src_group = msg.group.lower()
            if src_group == self.provision_group:
                if msg.action in (constants.ACTION_ADD, constants.ACTION_UPDATE):
                    yield self.provision_subject(msg.subject, msg.attributes)
                elif msg.action == constants.ACTION_DELETE:
                    yield self.deprovision_subject(msg.subject, msg.attributes)
                elif msg.action == constants.ACTION_MEMBERSHIP_SYNC:
                    yield self.sync_members(msg.subjects, msg.attributes)
                else:
                    raise UnknownActionError(
                        "Don't know how to handle action '{0}' for provisioning.".format(msg.action))
            else:
                log.warn(
                    "Not sure what to do with group '{group}'.  Discarding ...",
                    group=src_group)
        except Exception as ex:
            log.warn("Error provisioning message: {error}", error=ex)
            tb = traceback.format_exc()
            log.debug("{traceback}", traceback=tb)
            raise

    def get_config_defaults(self):
        return dedent("""\
            [PROVISIONER]
            """)

    def parse_message(self, msg):
        """
        Parse message into a standard form.
        """
        log = self.log
        provision_group = self.provision_group
        serialized = msg.content.body
        doc = json.loads(serialized)
        action = doc['action']
        group = doc['group'].lower()
        single_subject_actions = (
            constants.ACTION_ADD,
            constants.ACTION_DELETE,
            constants.ACTION_UPDATE)
        if action in single_subject_actions:
            subject = doc['subject'].lower()
            attributes = None
            attributes = doc['attributes']
            return ParsedSubjectMessage(action, group, subject, attributes)
        elif action == constants.ACTION_MEMBERSHIP_SYNC:
            subjects = doc['subjects']
            attributes = doc['attributes']
            return ParsedSyncMessage(action, group, subjects, attributes)
        raise Exception("Could not parse message: {}".format(msg))

    @inlineCallbacks
    def get_ldap_client_(self):
        """
        Get an authenticated LDAP client.
        """
        endpoint_s = self.endpoint_s
        bind_dn = self.bind_dn
        bind_passwd = self.bind_passwd
        base_dn = self.base_dn
        reactor = self.reactor
        e = clientFromString(reactor, endpoint_str)
        client = yield connectProtocol(e, ldapclient.LDAPClient())
        yield client.startTLS()
        yield client.bind(bind_dn, bind_passwd)
        defer.returnValue(client)

    @inlineCallbacks
    def get_all_enabled_entries_(self, client=None):
        """
        Return a set of the DNs of all the enabled entries bounded by the
        base DN and any extra filter.
        """
        log = self.log
        log.debug("Attempting to get DNs of all enabled entries.")
        if self.search_filter is None:
            search_filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        else:
            search_filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)){})".format(self.search_filter)
        if client is None:
            client = yield get_ldap_client_()
        o = ldapsyntax.LDAPEntry(client, base_dn)
        results = yield o.search(filterText=search_filter, attributes=None)
        dn_set = set([])
        for entry in results:
            dn_set.add(entry.dn)
        defer.returnValue(dn_set)

    def compose_account_(self, subject, attributes):
        """
        Create an internal account representation based on the subject and/or
        attributes by using the configured template.

        The composed account must be a mapping with the following keys:
        * dn
        * userPrincipalName
        """
        log = self.log
        account_template = self.account_template_
        subject_info = dict(subject=subject, attributes=attributes)
        string_rep = account_template.render(subject_info)
        account = commentjson.parse(string_rep)
        assert "dn" in account, "Account template must create a 'dn' key."
        assert "userPrincipalName" in account, "Account template must create a 'userPrincipalName' key."
        return account

    @inlineCallbacks
    def sync_members(self, subjects, attrib_map):
        """
        Sync all local subjects to remote accounts.
        (Except non-managed accounts).
        """
        log = self.log
        reactor = self.reactor
        subject_list = [s.lower() for s in subjects]
        subject_list.sort()
        client = yield self.get_ldap_client_()
        with LDAPClientManager(client, active=True) as c:
            dn_set = yield self.get_all_enabled_entries(client=c)
            for subject in subject_list:
                attributes = attrib_map[subject]
                account = self.compose_account_(subject, attritbutes)
                dn = account['dn']
                yield self.provision_subject_(account, client=c)
                dn_set.discard(dn)
            for dn in dn_set:
                yield self.disable_dn_(dn, client=c) 

    @inlineCallbacks
    def provision_subject_(self, account, client=None):
        """
        Provision subject from internal account representation.
        """
        log = self.log
        attribs = {}
        dn = None
        for attrib, value in account.items():
            if attrib == 'dn':
                dn = value
                continue
            attribs.setdefault(attrib, set([])).add(value)
        if dn is None:
            raise Exception("Template needs to include `dn`!")
        ldap_attrs = []
        for attrib, values in attribs.items():
            ldap_attrib_type = pureldap.LDAPAttributeDescription(attrib)
            l = []
            for value in values:
                if (isinstance(value, unicode)):
                    value = value.encode('utf-8')
                l.append(pureldap.LDAPAttributeValue(value))
            ldap_values = pureber.BERSet(l)
            ldap_attrs.append((ldap_attrib_type, ldap_values))
        op = pureldap.LDAPAddRequest(
            entry=str(dn),
            attributes=ldap_attrs)
        log.debug("LDAP ADD request: {add_req}", add_req=repr(op))
        unbind = False
        if client is None:
            client = yield self.get_ldap_client_()
            unbind = True
        with LDAPClientManager(client, active=unbind) as c:
            response = yield c.send(op)
        log.debug("LDAP ADD response: {add_resp}", add_resp=repr(response))

    @inlineCallbacks
    def provision_subject(self, subject, attributes):
        """
        Provision a subject to the remote service.
        """
        log = self.log
        log.debug(
            "Attempting to provision subject '{subject}'.",
            subject=subject)
        account = self.compose_account(subject, attritbutes)
        yield self.provision_subject_(account)

    @inlineCallbacks
    def disable_dn_(self, dn, client=None):
        """
        Deprovision subject based on DN.
        """
        log = self.log
        unbind = False
        if client is None:
            client = yield self.get_ldap_client_()
            unbind = True
        with LDAPClientManager(client, active=unbind) as c:
            o = ldapclient.LDAPClient(c, dn)
            results = yield o.search(filterText=self.search_filter, attributes=('userAccountControl',))
            if len(results) == 1:
                entry = results[0]
                ADS_UF_ACCOUNTDISABLE = 0x00000002
                user_account_control = int(list(entry['userAccountControl'])[0])
                user_account_control = (user_account_control | ADS_UF_ACCOUNTDISABLE)
                mod = delta.ModifyOp(
                    dn,
                    [
                        delta.Replace('userAccountControl', ["{}".format(user_account_control)]),
                    ])
                l = mod.asLDAP()
                response = yield client.send(l)

    @inlineCallbacks
    def deprovision_subject(self, subject, attributes):
        """
        Deprovision a subject from the remote service.
        """
        log = self.log
        log.debug("Entered deprovision_subject().")
        account = self.compose_account_(subject, attritbutes)
        dn = account['dn']
        yield self.disable_dn_(dn)
        
