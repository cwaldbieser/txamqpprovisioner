
from __future__ import print_function
from commentjson import load as load_json
from twisted.internet import defer
from twisted.plugin import IPlugin
from zope.interface import implements
from interface import (
    IRouterFactory,
    IRouter,
)
from errors import (
    NoMatchingRouteError,
)
from kikiroute import RouteInfo
import attr


class JSONRouterFactory(object):
    implements(IPlugin, IRouterFactory)
    tag = "json_router"

    def generate_router(self, config_parser):
        """
        Create an object that implements IRouter.
        """
        section = "JSON Router"
        options = config_parser.options(section)
        path = config_parser.get(section, "json_file")
        router = JSONRouter(path) 
        return router


class JSONRouter(object):
    implements(IRouter)
    log = None

    def __init__(self, path):
        """
        JSON routing map format:

        [
            {
                "name": "Splunk",
                "stem": "lc:app:splunk:exports",
                "recursive": false,
                "include_attributes": false,
                "include_group_attributes": false,
                "route_key": "splunk"
            },
            {
                "name": "VPN",
                "group": "lc:app:vpn:vpn",
                "include_attributes": false,
                "route_key": "vpn"
            },
            {
                "name": "OrgSync",
                "stem": "lc:app:orgsync:exports",
                "include_attributes": true,
                "allow_actions": ["add", "delete", "update"],
                "route_key": "orgsync"
            },
            {
                "name": "Default",
                "group": "*",
                "discard": true
            }
        ]
        """
        with open(path, "r") as f:
            doc = load_json(f)
        self.create_route_map(doc)

    def create_route_map(self, doc):
        """
        Create the internal routing map from the JSON representiation.
        """
        log = self.log
        routes = []
        for n, entry in enumerate(doc):
            route_entry = RouteEntry(entry)
            validate_route_entry_(route_entry)
            routes.append(route_entry)
        self.routes = routes

    def get_route(self, instructions, groups):
        """
        Return a Deferred that fires with a RouteEntry
        object or raises a NoMatchingRouteError.
        If a message should be discarded, the route should
        map to None.
        """
        log = self.log
        action = instructions.action
        routes = self.routes
        route_keys = []
        attributes_required = False
        group_attributes_required = False
        for group in groups:
            matched = False
            for route in routes:
                log.debug(
                    "Testing group '{group}' and action '{action}' against possible routes.",
                    group=group,
                    action=action)
                if self.match_route_(route, group, action):
                    log.debug("Matched route entry: {route_entry}", route_entry=route)
                    matched = True
                    if route.discard:
                        log.debug(
                            "Discarding group '{group}' from routing consideration.",
                            group=group)
                        break
                    else:
                        route_keys.append(route.route_key)
                        log.debug("Added route key: '{route_key}'", route_key)
                        attributes_required = attributes_required or route.include_attributes
                        group_attributes_required = group_attributes_required or route.include_group_attributes
                        break
            if not matched:
                raise NoMatchingRouteError(
                    "There is not route that matches group '{0}'.".format(
                        group))
        if len(route_keys) == 0:
            route_info = RouteInfo()
        else:
            route_keys = list(set(route_keys))
            route_keys.sort()
            route_info = RouteInfo(
                '.'.join(route_keys),
                attributes_required,
                group_attributes_required
            )
        return defer.succeed(route_info)

    def match_route_(self, route_entry, group, action):
        """
        Return True if the group matches the entry; False otherwise.
        """
        log = self.log
        allowed_actions = route_entry.allowed_actions
        log.debug("Candidate entry: {route_entry}", route_entry=route_entry)
        if route_entry.group == group or route_entry.group == "*":
            if (len(allowed_actions) == 0) or action in allowed_actions:
                return True
        elif (route_entry.stem is not None) and group.startswith(route_entry.stem):
            if route_entry.recursive:
                if (len(allowed_actions) == 0) or action in allowed_actions:
                    return True
            suffix = group[len(route_entry.stem):]
            if ":" not in suffix:
                if (len(allowed_actions) == 0) or action.lower() in allowed_actions:
                    return True
        return False


class JSONRouteEntryError(Exception):
    pass


@attr.attrs
class RouteEntry(object):
    group = attr.attrib()        
    stem = attr.attrib()
    route_key = attr.attrib()
    allowed_actions = attr.attrib(default=attr.Factory(set))
    recursive = attr.attrib(default=False, converter=bool)
    include_attributes = attr.attrib(default=False, converter=bool)
    include_group_attributes = attr.attrib(default=False, converter=bool)
    discard = attr.attrib(default=False, converter=bool)


def validate_route_entry_(entry):
    """
    Validate an normalize a RouteEntry.
    """
    if (entry.group is not None) and (entry.stem is not None):
        msg = (
            "Cannot have both 'group' and 'stem' patterns "
            "in a route entry number {0}.").format(n+1)
        raise JSONRouteEntryError(msg)
    if (entry.group is None) and (entry.stem is None):
        msg = (
            "Must have either 'group' or 'stem' pattern "
            "in route entry number {0}.").format(n+1)
        raise JSONRouteEntryError(msg)
    entry.allowed_actions = set(action.lower() for action in entry.allowed_actions)
    if (entry.stem is not None) and (not entry.stem.endswith(":")):
        entry.stem = "{}:".format(entry.stem)
    if entry.stem is None and entry.recursive:
        msg = (
            "'recursive' property is only valid for 'stem' pattern"
            "in route entry {}.").format(entry)
        raise JSONRouteEntryError(msg)
    if entry.route_key is None and not entry.discard:
        msg = (
            "Missing 'route_key' "
            "in route entry {}.").format(entry)
        raise JSONRouteEntryError(msg)
    if entry.discard and entry.include_attributes:
        msg = (
            "'include_attributes' and 'discard' are mutally exclusive "
            "in route entry {}.").format(entry)
        raise JSONRouteEntryError(msg)
    if entry.discard and entry.route_key is not None:
        msg = (
            "'route_key' and 'discard' are mutally exclusive "
            "in route entry {}.").format(entry)
        raise JSONRouteEntryError(msg)


@attr.attrs
class RouteInfo(object):
    route_key = attr.attrib(default=None)        
    attributes_required = attr.attrib(default=False)
    group_attributes_required = attr.attrib(default=False)


