from __future__ import print_function

import datetime
import json
import time

import jwt
from rest_provisioner import (OptionMissingError, RESTProvisioner,
                              RESTProvisionerFactory, StringProducer)
from twisted.internet.defer import inlineCallbacks, returnValue


class ZoomProvisioner(RESTProvisioner):
    """
    Definitions:

    * match_value: Can be computed on either the local or remote side.
      On the local side, the subject and attributes can be used to compute it.
      On the remote side, any of the remote account attributes can be used to
      compute it.
    * local_id: The local ID used to refer to the subject.  The subject value
      received in the message to the provisioner.
    * api_id: The identifier used by the REST API to refer to a remote account.
    * unmanaged_id: Some remote accounts are specific to the remote service and
      should not be managed by the provisioner (e.g. a back door admin account).
      These accounts are identified by their match_values.
    """

    client_id = None
    new_user_type = 2  # Pro
    jwt_expiration_seconds = 30
    user_list_page_size = 100
    max_page_loops = 1000
    update_status = True
    update_license = False

    def get_match_value_from_remote_account(self, remote_account):
        """
        Given a remote account, `remote_account`, extract the
        value that will be used to match the remote account
        to the local subject.
        Returns None if a match value cannot be constructed for the remote
        account.
        """
        assert remote_account is None, "`remote_account` is not None!"
        match_value = remote_account.get("email", None)
        if match_value is not None:
            match_value = match_value.lower()
        return match_value

    def get_match_value_from_local_subject(self, subject, attributes):
        """
        Given a local subject and attributes, compute the value that
        will be used to match the remote account to the local subject.
        """
        assert (
            attributes is not None
        ), "get_match_value_from_local_subject(): `attributes` is None!"
        mail = attributes.get("mail", [None])[0]
        if mail is not None:
            mail = mail.lower()
        return mail

    def get_api_id_from_remote_account(self, remote_account):
        """
        Given a remote account, `remote_account`, extract the
        value that is used as an account identifier in API
        calls that reference the account.
        """
        assert remote_account is None, "`remote_account` is not None!"
        return remote_account.get("id", None)

    def parse_config(self, scp):
        """
        Parse any additional configuration this provisioner might need.
        """
        log = self.log
        config = self.config
        client_id = config.get("client_id", None)
        if client_id is None:
            raise OptionMissingError("Option `client_id` is required.")
        self.client_id = client_id
        new_user_type = int(config.get("new_user_type", "2"))
        self.new_user_type = new_user_type
        jwt_expiration_seconds = int(config.get("jwt_expiration_seconds", "30"))
        self.jwt_expiration_seconds = jwt_expiration_seconds
        user_list_page_size = int(config.get("user_list_page_size", "100"))
        self.user_list_page_size = user_list_page_size
        update_status = tobool(config.get("update_status", "yes"))
        self.update_status = update_status
        log.debug("update_status: {update_status}", update_status=update_status)
        update_license = tobool(config.get("update_license", "yes"))
        self.update_license = update_license
        log.debug("update_license: {update_license}", update_license=update_license)

    @inlineCallbacks
    def api_get_auth_token(self):
        """
        Make API call to obtain valid auth token.
        Should set `self.auth_token`.
        Logic in the REST provisioner will attempt to determine if an
        authorization token has expired and needs to be renewed.  This
        method will be called when that happens.

        .. note::

            Some APIs don't require a separate step for obtaining an authorization
            token.  In that case, just set `self.auth_token` to True.  The actual
            authorization of a HTTP request occurs in `authorize_api_call()`.
            In that method, you may use `self.auth_token` or not.

            E.g. If a request uses a simple shared secret for authorization, or
            a JSON web token (JWT) which is based on time and a shared secret, then
            `self.auth_token` would not be relevant to authorization.  Instead,
            `self.client_secret` would likely be used directly.
        """
        if False:
            yield None
        self.auth_token = True
        returnValue(None)

    @inlineCallbacks
    def authorize_api_call(self, method, url, **http_options):
        """
        Given the components of an *unauthenticated* HTTP client request,
        return the components of an authenticated request.

        Should return a tuple of (method, url, http_options)
        """
        log = self.log
        log.debug("Authorizing API call ...")
        if False:
            yield "Required for inlineCallbacks-- can't wait for async/await!"
        api_secret = self.client_secret
        api_key = self.client_id
        expiration = datetime.datetime.utcnow() + datetime.timedelta(
            seconds=self.jwt_expiration_seconds
        )
        expiration_ts = int(time.mktime(expiration.timetuple()))
        payload = {"iss": api_key, "exp": expiration_ts}
        encoded = jwt.encode(payload, api_secret, algorithm="HS256")
        headers = http_options.setdefault("headers", {})
        headers["Authorization"] = ["Bearer {}".format(encoded)]
        returnValue((method, url, http_options))

    @inlineCallbacks
    def get_all_api_ids_and_match_values(self):
        """
        Load all the remote API IDs and match values from the
        user accounts that exist on the remote service.
        Note: If a match value cannot be constructed for a remote
        account, it will not be included in the output of this function.
        """
        log = self.log
        log.debug("Attempting to fetch local IDs from all remote user accounts ...")
        ids = []
        for status in ("active", "inactive", "pending"):
            partial_ids = yield self.get_all_api_ids_and_match_values__(status=status)
            ids.extend(partial_ids)
        returnValue(ids)

    @inlineCallbacks
    def get_all_api_ids_and_match_values__(self, status="active"):
        """
        Load all the remote API IDs and match values from the
        user accounts that exist on the remote service and have status `status`.
        Note: If a match value cannot be constructed for a remote
        account, it will not be included in the output of this function.
        """
        log = self.log
        func_name = "get_all_api_ids_and_match_values__()"
        new_user_type = self.new_user_type
        prefix = self.url_prefix
        user_list_page_size = self.user_list_page_size
        url = "{}/users".format(prefix)
        headers = {
            "Accept": ["application/json"],
        }
        params = {"page_size": user_list_page_size, "status": status}
        identifiers = []
        for n in range(self.max_page_loops):
            page_number = n + 1
            params["page_number"] = page_number
            log.debug("URL (GET): {url}", url=url)
            log.debug("headers: {headers}", headers=headers)
            log.debug("headers: {params}", params=params)
            try:
                resp = yield self.make_authenticated_api_call(
                    "GET", url, headers=headers, params=params
                )
            except Exception:
                log.error("Error fetching all remote user data.")
                raise
            if resp.code != 200:
                body = yield resp.text()
                raise Exception(
                    "{}: status={}; received HTTP response code {}:\n{}".format(
                        func_name, status, resp.code, body
                    )
                )
            parsed = yield resp.json()
            received_page_number = parsed["page_number"]
            received_page_count = parsed["page_count"]
            users = parsed["users"]
            for user in users:
                user_type = user["type"]
                if user_type != new_user_type:
                    # Users are partitioned by license type, so a list of "all users"
                    # should only see users of the same type the provisioner handles.
                    continue
                remote_id = self.get_api_id_from_remote_account(user)
                match_value = self.get_match_value_from_remote_account(user)
                identifiers.append((remote_id, match_value))
            if received_page_number == received_page_count:
                break
            if page_number != received_page_number:
                log.warn(
                    "{func_name}: Page number requested and "
                    "received do not match: {page_number}, {received_page_number}",
                    func_name=func_name,
                    page_number=page_number,
                    received_page_number=received_page_number,
                )
                break
        returnValue(identifiers)

    @inlineCallbacks
    def api_get_remote_account(self, api_id):
        """
        Get the remote account information using its API ID.
        If the remote account cannot be found, return None.
        """
        log = self.log
        func_name = "api_get_remote_account()"
        log.debug("Attempting to fetch remote account ...")
        prefix = self.url_prefix
        url = "{}/users/{}".format(prefix, api_id)
        headers = {
            "Accept": ["application/json"],
        }
        log.debug("URL (GET): {url}", url=url)
        log.debug("headers: {headers}", headers=headers)
        resp = yield self.make_authenticated_api_call("GET", url, headers=headers)
        resp_code = resp.code
        remote_account = yield resp.json()
        if resp_code not in (200, 400, 404):
            raise Exception(
                "{}: API call to fetch remote subject returned HTTP status {}".format(
                    func_name, resp_code
                )
            )
        if resp_code == 400:
            if remote_account.get("message") == "User not belong to this account":
                log.warn("Could not retrieve account in URL: {url}.", url=url)
                remote_account = None
            else:
                raise Exception(
                    "{}: API call to fetch remote subject returned HTTP status {}".format(
                        func_name, resp_code
                    )
                )
        if resp_code == 404:
            remote_account = None
        returnValue(remote_account)

    @inlineCallbacks
    def api_deprovision_subject(self, api_id):
        """
        Make the API call require to deprovision the subject identified by
        `api_id`.
        """
        if self.update_status:
            yield self.api_set_account_status_("deactivate", api_id)

    @inlineCallbacks
    def api_get_account_id(self, subject, attributes):
        """
        Fetch the remote ID for a subject.
        Return None if the account does not exist on the remote end.
        """
        log = self.log
        func_name = "api_get_account_id"
        log.debug("Entered {func_name}", func_name=func_name)
        match_value = self.get_match_value_from_local_subject(subject, attributes)
        # Note: While `api_get_remote_account() takes an API ID as a parameter, for the Zoom
        # API, the email address, which also happens to be the match value, can be used
        # interchangeably with it in API calls.  Therefore, it is entirely reasonable to
        # use the match value to obtain the API ID directly *for this specific provisioner.*
        account = yield self.api_get_remote_account(match_value)
        if account is not None:
            api_id = account.get("id", None)
        else:
            api_id = None
        returnValue(api_id)

    @inlineCallbacks
    def api_activate_account_(self, api_id):
        """
        Call the Zoom API to set an account's status to active.
        """
        if self.update_status:
            yield self.api_set_account_status_("activate", api_id)

    @inlineCallbacks
    def api_set_account_status_(self, status, api_id):
        """
        Call the Zoom API to set an account status.
        """
        log = self.log
        func_name = "api_set_account_status_()"
        if status == "deactivate":
            allowed_response_codes = (204, 404)
        else:
            allowed_response_codes = (204,)
        prefix = self.url_prefix
        url = "{}/users/{}/status".format(prefix, api_id)
        headers = {
            "Accept": ["application/json"],
            "Content-Type": ["application/json"],
        }
        props = {
            "action": status,
        }
        serialized = json.dumps(props)
        body = StringProducer(serialized.encode("utf-8"))
        log.debug("url: {url}", url=url)
        log.debug("headers: {headers}", headers=headers)
        log.debug("body: {body}", body=serialized)
        resp = yield self.make_authenticated_api_call(
            "PUT", url, headers=headers, data=body
        )
        resp_code = resp.code
        try:
            content = yield resp.content()
        except Exception:
            pass
        if resp_code not in allowed_response_codes:
            raise Exception(
                (
                    "{}: API call to set account status "
                    "to '{}' returned HTTP status {}\n{}"
                ).format(func_name, status, resp_code, content)
            )
        returnValue(None)

    @inlineCallbacks
    def api_update_subject(self, subject, api_id, attributes):
        """
        Make API request to update remote account.
        Returns the HTTP response.
        """
        log = self.log
        assert attributes is not None, "api_update_subject(): `attributes` is None!"
        # If you are updating a subject, it must be active (i.e. provisioned).
        # Therefor, it's state in Zoom must be set to active.
        yield self.api_activate_account_(api_id)
        prefix = self.url_prefix
        url = "{}/users/{}".format(prefix, api_id)
        headers = {
            "Accept": ["application/json"],
            "Content-Type": ["application/json"],
        }
        surname = attributes.get("sn", [""])[0]
        givenname = attributes.get("displayName", [""])[0]
        if givenname == "":
            givenname = attributes.get("givenName", [""])[0]
        new_user_type = self.new_user_type
        props = {
            "first_name": givenname,
            "last_name": surname,
        }
        if self.update_license:
            log.debug("Updating license type.")
            props["type"] = new_user_type
        serialized = json.dumps(props)
        body = StringProducer(serialized.encode("utf-8"))
        log.debug("url: {url}", url=url)
        log.debug("headers: {headers}", headers=headers)
        log.debug("body: {body}", body=serialized)
        resp = yield self.make_authenticated_api_call(
            "PATCH", url, data=body, headers=headers
        )
        returnValue(resp)

    @inlineCallbacks
    def api_add_subject(self, subject, attributes):
        """
        Use the API to add subjects.

        Returns the API ID of the newly created remote account or None.
        If None is returned, the API ID will not be cached and require
        a lookup on future use.
        """
        log = self.log
        assert attributes is not None, "api_add_subject(): `attributes` is None!"
        func_name = "api_add_subject()"
        log.debug("Entered: {func_name}", func_name=func_name)
        prefix = self.url_prefix
        url = "{}/users".format(prefix)
        headers = {
            "Accept": ["application/json"],
            "Content-Type": ["application/json"],
        }
        surname = attributes.get("sn", [""])[0]
        givenname = attributes.get("displayName", [""])[0]
        if givenname == "":
            givenname = attributes.get("givenName", [""])[0]
        email = attributes.get("mail", [""])[0]
        user_info = {
            "email": email,
            "type": self.new_user_type,
            "first_name": givenname,
            "last_name": surname,
        }
        props = {
            "action": "ssoCreate",
            "user_info": user_info,
        }
        serialized = json.dumps(props)
        body = StringProducer(serialized.encode("utf-8"))
        log.debug("url: {url}", url=url)
        log.debug("headers: {headers}", headers=headers)
        log.debug("body: {body}", body=serialized)
        resp = yield self.make_authenticated_api_call(
            "POST", url, data=body, headers=headers
        )
        resp_code = resp.code
        log.debug(
            "{func_name}: Add-subject API response code: {code}",
            func_name=func_name,
            code=resp_code,
        )
        if resp_code != 201:
            log.warn(
                "There was an issue adding subject `{subject}` with attributes: {attributes}.",
                subject=subject,
                attributes=attributes,
            )
            yield resp.content()
            raise Exception("{}: API returned status {}".format(func_name, resp_code))
        parsed = yield resp.json()
        api_id = self.get_match_value_from_remote_account(parsed)
        returnValue(api_id)

    @inlineCallbacks
    def api_add_subject_to_group(self, subject_id, target_group_id):
        """
        Make an authenticated API call to add the remote subject ID
        to the remote group ID.
        Should raise on error on failure.
        """
        log = self.log
        func_name = "api_add_subject_to_group()"
        log.debug("Entered: {func_name}", func_name=func_name)
        prefix = self.url_prefix
        url = "{}/groups/{}/members".format(prefix, target_group_id)
        headers = {
            "Accept": ["application/json"],
            "Content-Type": ["application/json"],
        }
        props = {
            "members": [
                {
                    "id": subject_id,
                }
            ],
        }
        serialized = json.dumps(props)
        body = StringProducer(serialized.encode("utf-8"))
        log.debug("url: {url}", url=url)
        log.debug("headers: {headers}", headers=headers)
        log.debug("body: {body}", body=serialized)
        resp = yield self.make_authenticated_api_call(
            "POST", url, data=body, headers=headers
        )
        resp_code = resp.code
        if resp_code != 201:
            content = yield resp.content()
            # log.error(
            #    "{func_name}: API response {code}: {content}",
            #    func_name=func_name,
            #    code=resp_code,
            #    content=content)
            raise Exception(
                "{}: API returned status {}\n{}".format(func_name, resp_code, content)
            )
        yield resp.json()

    @inlineCallbacks
    def api_remove_subject_from_group(self, subject_id, target_group_id):
        """
        Make an authenticated API call to add the remote subject ID
        to the remote group ID.
        Should raise on error on failure.
        """
        log = self.log
        func_name = "api_remove_subject_from_group()"
        log.debug("Entered: {func_name}", func_name=func_name)
        prefix = self.url_prefix
        url = "{}/groups/{}/members/{}".format(prefix, target_group_id, subject_id)
        headers = {
            "Accept": ["application/json"],
            "Content-Type": ["application/json"],
        }
        log.debug("url: {url}", url=url)
        log.debug("headers: {headers}", headers=headers)
        resp = yield self.make_authenticated_api_call("DELETE", url, headers=headers)
        resp_code = resp.code
        if resp_code != 204:
            yield resp.content()
            # log.error(
            #    "{func_name}: API response {code}: {content}",
            #    func_name=func_name,
            #    code=resp_code,
            #    content=content)
            raise Exception("{}: API returned status {}".format(func_name, resp_code))
        yield resp.content()

    @inlineCallbacks
    def api_get_all_target_groups(self):
        """
        Load all target_groups from the service.
        Must return an iterable that yields tuples of
        (local_group_id, remote_group_id).
        """
        log = self.log
        func_name = "api_get_all_target_groups()"
        log.debug("Entered: {func_name}.", func_name=func_name)
        prefix = self.url_prefix
        url = "{}/groups".format(prefix)
        headers = {
            "Accept": ["application/json"],
            "Content-Type": ["application/json"],
        }
        log.debug("url: {url}", url=url)
        log.debug("headers: {headers}", headers=headers)
        resp = yield self.make_authenticated_api_call("GET", url, headers=headers)
        resp_code = resp.code
        if resp_code != 200:
            yield resp.content()
            # log.error(
            #    "{func_name}: API response {code}: {content}",
            #    func_name=func_name,
            #    code=resp_code,
            #    content=content)
            raise Exception("{}: API returned status {}".format(func_name, resp_code))
        parsed = yield resp.json()
        groups = parsed["groups"]
        group_id_list = []
        for entry in groups:
            api_id = entry["id"]
            local_id = entry["name"]
            group_id_list.append((local_id, api_id))
        returnValue(group_id_list)

    @inlineCallbacks
    def get_subjects_for_target_group(self, target_group_id):
        """
        Retrieve a list of remote subject IDs that belong to a target_group identified
        by remote target_group_id.
        """
        log = self.log
        func_name = "get_subjects_for_target_group()"
        prefix = self.url_prefix
        user_list_page_size = self.user_list_page_size
        url = "{}/groups/{}/members".format(prefix, target_group_id)
        headers = {
            "Accept": ["application/json"],
        }
        params = {
            "page_size": user_list_page_size,
        }
        identifiers = []
        for n in range(self.max_page_loops):
            page_number = n + 1
            params["page_number"] = page_number
            log.debug("URL (GET): {url}", url=url)
            log.debug("headers: {headers}", headers=headers)
            log.debug("headers: {params}", params=params)
            try:
                resp = yield self.make_authenticated_api_call(
                    "GET", url, headers=headers, params=params
                )
            except Exception:
                log.error("Error fetching all remote user data.")
                raise
            if resp.code != 200:
                body = yield resp.text()
                raise Exception(
                    "{}: Received HTTP response code {}:\n{}".format(
                        func_name, resp.code, body
                    )
                )
            parsed = yield resp.json()
            received_page_number = parsed["page_number"]
            received_page_count = parsed["page_count"]
            users = parsed["members"]
            for user in users:
                remote_id = self.get_api_id_from_remote_account(user)
                identifiers.append(remote_id)
            if received_page_number == received_page_count:
                break
            if page_number != received_page_number:
                log.warn(
                    "{func_name}: Page number requested and received "
                    "do not match: {page_number}, {received_page_number}",
                    func_name=func_name,
                    page_number=page_number,
                    received_page_number=received_page_number,
                )
                break
        returnValue(identifiers)


class ZoomProvisionerFactory(RESTProvisionerFactory):
    tag = "zoom_provisioner"
    opt_help = "Zoom REST API Provisioner"
    opt_usage = "This plugin does not support any options."
    provisioner_factory = ZoomProvisioner


def tobool(s):
    """
    Convert a collection of configuration values to a boolean value.
    """
    if s is None:
        return False
    s = str(s)
    if s[0] in "yYtT1":
        return True
    if s[0] in "nNfF0":
        return False
    raise ValueError("Cannot convert `{}` to a boolean value.".format(s))
