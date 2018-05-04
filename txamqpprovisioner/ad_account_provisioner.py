
from __future__ import print_function
import datetime
import json
import commentjson
import jinja2 
from textwrap import dedent
import traceback
import attr
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
        pass

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
    def get_all_enabled_entries_(self):
        """
        Return a set of the DNs of all the enabled entries bounded by the
        base DN and any extra filter.
        """
        log = self.log

    def compose_account_(self, subject, attributes):
        """
        Create an internal account representation based on the subject and/or
        attributes by using the configured template.
        """
        log = self.log

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
        dn_set = yield self.get_all_enabled_entries()
        for subject in subject_list:
            attributes = attrib_map[subject]
            account = self.compose_account(subject, attritbutes)
            dn = account['dn']
            yield self.provision_subject_(account)
            dn_set.discard(dn)
        for dn in dn_set:
            yield self.disable_dn(dn) 

    @inlineCallbacks
    def provision_subject_(self, account):
        """
        Provision subject from internal account representation.
        """
        log = self.log

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
    def deprovision_subject_(self, dn):
        """
        Deprovision subject based on DN.
        """
        log = self.log

    @inlineCallbacks
    def deprovision_subject(self, subject, attributes):
        """
        Deprovision a subject from the remote service.
        """
        log = self.log
        log.debug("Entered deprovision_subject().")
        account = self.compose_account(subject, attritbutes)
        dn = account['dn']
        yield self.deprovision_subject_(dn)
        

@inlineCallbacks
def delay(reactor, seconds):
    """
    A Deferred that fires after `seconds` seconds.
    """
    yield task.deferLater(reactor, seconds, lambda : None)

@inlineCallbacks
def delayUntil(reactor, t):
    """
    Delay until time `t`.
    If `t` is None, don't delay.

    `params t`: A datetime object or None
    """
    if t is None:
        returnValue(None)
    instant = datetime.datetime.today()
    if instant < t:
        td = t - instant
        delay_seconds = td.total_seconds()
        yield task.deferLater(reactor, delay_seconds, lambda : None)
    
