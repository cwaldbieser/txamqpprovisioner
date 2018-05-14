
from __future__ import print_function
import datetime
import json
import collections
import random
import string
from textwrap import dedent
import traceback
import attr
import commentjson
import jinja2 
from ldap_utils import escape_filter_chars, normalize_dn
from ldaptor import delta
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient, ldapsyntax
from ldaptor.protocols.ldap.distinguishedname import DistinguishedName, RelativeDistinguishedName
from ldaptor.protocols.ldap.distinguishedname import unescape as unescapeDN
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols import (
    pureber,
    pureldap
)
import pem
import six
from six import iteritems
from twisted.internet import defer, ssl
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

def iterable_not_string(arg):
    return isinstance(arg, collections.Iterable) and not isinstance(arg, six.string_types)

def generate_passwd(n=16):
    population = string.ascii_letters + string.digits + string.punctuation
    return ''.join([random.choice(population) for i in range(n)]) 

def escape_quote(s):
    """
    Escape quotes for use in JSON strings.
    """
    return s.replace('"', r'\"')

def encode_ad_passwd(u):
    """
    Encode a plain text password for use in the `unicodePwd` attribute.
    """
    quoted = '"{}"'.format(u)
    return quoted.encode('utf-16le')


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
    log = None
    def __init__(self, client, active=True, log=log):
        self.client_ = client
        self.active = active
        self.log = log

    def __enter__(self):
        if self.log:
            self.log.debug("Entering context manager.  Returning client: {client}", client=self.client_)
        return self.client_

    def __exit__(self, ex_type, ex_value, tb):
        if self.active:
            if self.log:
                self.log.debug("Exiting contect manager.  Issuing unbind.")
            self.client_.unbind()
        return (ex_type is None)
        

class ADAccountProvisionerFactory(object):
    implements(IPlugin, IProvisionerFactory)
    tag = "ad_account_provisioner"
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
    use_starttls = True
    starttls_hostname = None
    starttls_trust_anchor = None

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
                self.use_starttls = bool(config.get("use_starttls", True))
                self.starttls_hostname = config.get("starttls_hostname", "localhost")
                starttls_trust_anchor = config.get('starttls_trust_anchor', None)
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
            self.load_starttls_trust_anchor(starttls_trust_anchor)
        except Exception as ex:
            d = self.reactor.callLater(0, self.reactor.stop)
            log.failure("Provisioner failed to initialize: {}".format(ex))
            raise
        return defer.succeed(None)

    def load_starttls_trust_anchor(self, pem_path):
        """
        Load the startTLS trust anchor from a file in PEM format.
        """
        log = self.log
        if not self.use_starttls:
            return
        if pem_path is None:
            return
        starttls_hostname = six.u(self.starttls_hostname)
        log.debug("type: {type}, value: {value}", type=type(starttls_hostname), value=starttls_hostname)
        assert starttls_hostname is not None, "Must set option `starttls_hostname` when using `starttls_trust_anchor`."
        log.debug("Reading PEM file {pem_path}.", pem_path=pem_path)
        #with open(pem_path, "r") as f:
        #    data = f.read()
        #authority = ssl.Certificate.loadPEM(data)
        certs = pem.parse_file(pem_path)
        log.debug("Length `certs`: {len}", len=len(certs))
        for c in certs:
            log.debug("Cert: {cert}", cert=str(c))
        authority = ssl.Certificate.loadPEM('\n'.join(str(cert) for cert in certs))
        log.debug("StartTLS authority: {authority}", authority=authority.inspect())
        log.debug("StartTLS hostname: '{hostname}'", hostname=starttls_hostname)
        self.starttls_trust_anchor = ssl.optionsForClientTLS(starttls_hostname, authority)

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
            raise ex

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
        log = self.log
        endpoint_s = self.endpoint_s
        bind_dn = self.bind_dn
        bind_passwd = self.bind_passwd
        base_dn = self.base_dn
        reactor = self.reactor
        use_starttls = self.use_starttls
        starttls_trust_anchor = self.starttls_trust_anchor
        log.debug("Endpoint: {endpoint}", endpoint=endpoint_s)
        e = clientFromString(reactor, endpoint_s)
        client = yield connectProtocol(e, ldapclient.LDAPClient())
        if use_starttls:
            log.debug("StartTLS trust anchor: {trust}", trust=starttls_trust_anchor)
            yield client.startTLS(starttls_trust_anchor)
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
        log.info("Creating account from template.  Attributes: {attribs}", attribs=attributes)
        account_template = self.account_template_
        subject_info = dict(subject=subject, attributes=attributes)
        string_rep = account_template.render(subject_info)
        log.info("Textual representation of account: {text}", text=string_rep)
        account = commentjson.loads(string_rep)
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
                create_hint = (dn in dn_set)
                yield self.provision_subject_(account, client=c, create_hint=create_hint)
                dn_set.discard(dn)
            for dn in dn_set:
                yield self.disable_dn_(dn, client=c) 

    def entry_to_attribs_(self, entry):
        """
        Convert a simple mapping to the data structures required for an
        entry in the DIT.

        Returns: (dn, attributes)
        """
        attribs = {}
        dn = None
        for prop, value in entry.items():
            if prop == 'dn':
                dn = value.encode('utf-8')
                continue
            msg = (
                    "Account template value should be an iterable: "
                    "prop='{}', value='{}'"
                    ).format(prop, value)
            assert iterable_not_string(value), msg 
            attribs[prop] = set(value)
        if dn is None:
            raise Exception("Entry needs to include key, `dn`!")
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
        return dn, ldap_attrs

    @inlineCallbacks
    def provision_subject_(self, account, client=None, create_hint=False):
        """
        Provision subject from internal account representation.
        """
        log = self.log
        log.info("Entered provision_subject_()")
        if create_hint:
            strategies = [self.add_entry_, self.update_entry_]
        else:
            strategies = [self.update_entry_, self.add_entry_]
        log.info("Chose provision strategy.")
        result_codes = []
        success = False
        for strategy in strategies:
            result_code = yield strategy(account, client)
            if result_code == 0:
                returnValue(None)
            result_codes.append(result_code)
        log.debug("Couldn't create or update entry.")
        log.debug("account: {}".format(account))
        log.debug("result codes: {}".format(result_codes))
        raise Exception("Could not create nor update entry.") 

    @inlineCallbacks
    def add_entry_(self, account, client):
        """
        Attempt to add an LDAP entry.
        """
        log = self.log
        log.info("Entered add_entry_()")
        if not 'unicodePwd' in account:
            account['unicodePwd'] = [encode_ad_passwd(generate_passwd())]
        dn, attributes = self.entry_to_attribs_(account)
        op = pureldap.LDAPAddRequest(
            entry=dn,
            attributes=attributes)
        log.debug("LDAP ADD request: {add_req}", add_req=repr(op))
        unbind = False
        if client is None:
            client = yield self.get_ldap_client_()
            unbind = True
        with LDAPClientManager(client, active=unbind) as c:
            response = yield c.send(op)
        log.debug("LDAP ADD response: {add_resp}", add_resp=repr(response))
        result_code = response.resultCode
        allowed_results = (
            ldaperrors.Success.resultCode, 
            ldaperrors.LDAPEntryAlreadyExists.resultCode)
        if result_code not in allowed_results:
            msg = response.errorMessage
            raise Exception("Error adding entry: result_code={}, msg={}".format(
                result_code, msg))
        returnValue(result_code)

    @inlineCallbacks
    def update_entry_(self, account, client):
        """
        Attempt to update and LDAP entry.
        """
        log = self.log
        log.info("Entered update_entry_()")
        updateable_attribs = {
            "givenName",
            "displayName",
            "sn",
            "userAccountControl",
        }
        attribs = [delta.Replace(prop, list(values)) 
            for prop, values in account.items() if prop in updateable_attribs]  
        log.debug("attribs: {attribs}", attribs=attribs)
        try:
            dn = account['dn']
        except KeyError:
            raise Exception("Account template must include a `dn` property.")
        mod = delta.ModifyOp(dn, attribs)
        log.debug("LDAP MOD request: {mod_req}", mod_req=repr(mod))
        unbind = False
        if client is None:
            client = yield self.get_ldap_client_()
            unbind = True
        response = None
        log.debug("LDAPClientManager unbind flag: {unbind}", unbind=unbind)
        with LDAPClientManager(client, active=unbind, log=log) as c:
            log.debug("Sending LDAP MOD request.")
            response = yield c.send(mod.asLDAP())
            log.debug("LDAP MOD request sent.  Response: {resp}", resp=repr(response))
        log.debug("LDAP MOD response: {mod_resp}", mod_resp=repr(response))
        result_code = response.resultCode
        allowed_results = (
            ldaperrors.Success.resultCode, 
            ldaperrors.LDAPNoSuchObject.resultCode)
        if result_code not in allowed_results:
            msg = response.errorMessage
            raise Exception("Error adding entry: result_code={}, msg={}".format(
                result_code, msg))
        returnValue(result_code)

    @inlineCallbacks
    def provision_subject(self, subject, attributes):
        """
        Provision a subject to the remote service.
        """
        log = self.log
        log.debug(
            "Attempting to provision subject '{subject}'.",
            subject=subject)
        account = self.compose_account_(subject, attributes)
        log.info("Account has been composed.")
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
            o = ldapsyntax.LDAPEntry(c, dn)
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
        account = self.compose_account_(subject, attributes)
        dn = account['dn']
        yield self.disable_dn_(dn)
        
