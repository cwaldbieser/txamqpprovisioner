
from __future__ import print_function
import itertools
import json
import random
import string
import urlparse
import commentjson
from rest_provisioner import (
    APIResponseError,
    OptionMissingError,
    RESTProvisioner,
    RESTProvisionerFactory, 
    StringProducer,
)
from twisted.internet.defer import (
    inlineCallbacks, 
    returnValue,
)


class CrashplanProvisioner(RESTProvisioner):
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
    api_username = None
    page_size = 100
    
    def get_match_value_from_remote_account(self, remote_account):
        """
        Given a remote account, `remote_account`, extract the
        value that will be used to match the remote account 
        to the local subject.
        Returns None if a match value cannot be constructed for the remote
        account.
        """
        log = self.log
        domain = self.domain
        match_value = remote_account.get("email", None)
        if match_value is not None:
            match_value = match_value.lower()
            if not match_value.endswith("@{}".format(domain.lower())):
                match_value = None
        return match_value

    def get_match_value_from_local_subject(self, subject, attributes):
        """
        Given a local subject and attributes, compute the value that
        will be used to match the remote account to the local subject.
        """
        domain = self.domain
        return "{0}@{1}".format(subject, domain)

    def get_api_id_from_remote_account(self, remote_account):
        """
        Given a remote account, `remote_account`, extract the
        value that is used as an account identifier in API
        calls that reference the account.
        """
        return remote_account.get("userId", None)

    def parse_config(self, scp):
        """
        Parse any additional configuration this provisioner might need.
        """
        log = self.log
        config = self.config
        api_username = config.get("api_username", None)
        if api_username is None:
            raise OptionMissingError(
                "The `api_username` option is missing!") 
        self.api_username = api_username
        self.page_size = config.get("page_size", 100)
        domain = config.get("domain", None)
        if domain is None:
            raise OptionMissingError(
                "The `domain` option is missing!") 
        self.domain = domain

    @inlineCallbacks
    def api_get_auth_token(self):
        """
        Make API call to obtain valid auth token.
        Should set `self.auth_token`.
        """
        log = self.log
        log.debug("entered api_get_auth_token().")
        domain = self.domain
        http_client = self.http_client
        headers = {
            'Accept': ['application/json'],
        }
        client_secret = self.client_secret
        params = {
            "useBody": "true",
        }
        basic_auth = (self.api_username, self.client_secret)
        auth_url = "{}/c42api/v3/auth/jwt".format(self.url_prefix)
        log.debug("Making API call to obtain auth token ...")
        log.debug("method: GET, URL: {url}", url=auth_url)
        log.debug("auth: ({}, {}***)".format(basic_auth[0], basic_auth[1][:3]))
        response = yield http_client.get(
            auth_url,
            auth=basic_auth,
            params=params,
            headers=headers)
        resp_code = response.code
        log.debug("API call to obtain token is complete.  Response code: {code}", code=resp_code)
        if resp_code == 200:
            try:
                doc = yield response.json()
            except Exception as ex:
                log.error("Error attempting to parse response to authentication request.")
                raise
            if not "data" in doc:
                log.error("Error attempting to parse response to authentication request.")
                raise Exception("Error parsing authentication response.  Missing element `data`.")
            data = doc['data']
            if not "v3_user_token" in data:
                log.error("Error attempting to parse response to authentication request.")
                raise Exception("Error parsing authentication response.  Missing element `v3_user_token`.")
            self.auth_token = data["v3_user_token"]
            log.debug("New auth token obtained.")
        else:
            self.check_unauthorized_response(response)
            content = yield response.content()
            raise Exception(
                "Unable to obtain valid auth token.  Response {}: {}".format(
                response_code=resp_code,
                content=content)
            )

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
        auth_token = self.auth_token
        headers = http_options.setdefault("headers", {})
        headers["Authorization"] = ["v3_user_token {}".format(auth_token)]
        returnValue((method, url, http_options))

    @inlineCallbacks
    def get_all_api_ids_and_match_values(self):
        """
        Load all the remote subject IDs and match values from the 
        user accounts that exist on the remote sevice.
        Note: If a match value cannot be constructed for a remote
        account, it will not be included in the output of this function.
        """
        log = self.log
        log.debug("Attempting to fetch local IDs from all remote user accounts ...")
        http_client = self.http_client
        prefix = self.url_prefix
        url = "{}/api/User".format(prefix)
        page_size = self.page_size
        headers = {
            'Accept': ['application/json'],
        }
        params = {
            'pgSize': page_size
        }
        identifiers = []
        pg_num = 0
        while True:
            pg_num += 1
            params['pgNum'] = pg_num
            log.debug("URL (GET): {url}", url=url)
            log.debug("headers: {headers}", headers=headers)
            log.debug("params: {params}", params=params)
            try:
                resp = yield self.make_authenticated_api_call(
                    "GET",
                    url,
                    headers=headers,
                    params=params)
            except Exception as ex:
                log.error("Error fetching all remote user data.")
                raise
            parsed = yield resp.json()
            data = parsed.get("data", None)
            if data is None:
                log.error("Error attempting to parse response to get ALL users.")
                raise Exception("Error attempting to parse response to get ALL users.  Missing `data` element.")
            total_count = parsed.get("totalCount", -1)
            users = data.get("users", None)
            if users is None:
                log.error("Error attempting to parse response to get ALL users.")
                raise Exception("Error attempting to parse response to get ALL users.  Missing `users` element.")
            for entry in users:
                api_id = self.get_api_id_from_remote_account(entry)
                match_value = self.get_match_value_from_remote_account(entry)
                if not match_value is None:
                    identifiers.append((api_id, match_value))
            if len(users) < page_size:
                break
        returnValue(identifiers)

    @inlineCallbacks
    def api_get_remote_account(self, api_id):
        """
        Get the remote account information using its API ID.
        """
        log = self.log
        log.debug("entered api_get_remote_account().")
        log.debug("Attempting to fetch remote account ...")
        http_client = self.http_client
        prefix = self.url_prefix
        url = "{}/api/User/{}".format(prefix, api_id)
        headers = {
            'Accept': ['application/json'],
        }
        identifiers = []
        log.debug("URL (GET): {url}", url=url)
        log.debug("headers: {headers}", headers=headers)
        resp = yield self.make_authenticated_api_call(
            "GET",
            url,
            headers=headers)
        remote_account = yield resp.json()
        returnValue(remote_account)

    @inlineCallbacks
    def change_subject_status_(self, api_id, active=True):
        """
        Activate / deactivate subject.
        """
        log = self.log
        http_client = self.http_client
        prefix = self.url_prefix
        url = "{}/console/api/UserDeactivation/{}".format(prefix, api_id)
        headers = {
            'Accept': ['application/json'],
            'Content-Type': ['application/json'],
        }
        if active:
            method = "DELETE"
        else:
            method = "PUT"
        log.debug("url: {url}", url=url)
        log.debug("menthod: {method}", method=method)
        log.debug("headers: {headers}", headers=headers)
        resp = yield self.make_authenticated_api_call(
            method,
            url,
            headers=headers)
        resp_code = resp.code
        try:
            content = yield resp.content()
        except Exception as ex:
            pass
        returnValue(resp_code)

    @inlineCallbacks
    def api_deprovision_subject(self, api_id):
        """
        Make the API call require to deprovision the subject identified by
        `api_id`.
        """
        log = self.log
        log.debug("entered api_deprovision_subject()")
        resp_code = yield self.change_subject_status_(api_id, active=False)
        if resp_code != 201:
            raise Exception("API call to deprovision subject returned HTTP status {}".format(resp_code))
        returnValue(None)

    @inlineCallbacks
    def api_get_account_id(self, subject, attributes):
        """
        Fetch the remote ID for a subject.
        Return None if the account oes not exist on the remote end.
        """
        log = self.log
        log.debug("entered api_get_account()")
        http_client = self.http_client
        prefix = self.url_prefix
        local_match_value = self.get_match_value_from_local_subject(subject, attributes)
        url = "{}/api/User".format(prefix)
        headers = {
            'Accept': ['application/json'],
        }
        params = {
            'username': local_match_value,
        }
        log.debug("Making API call to fetch account from local match value.")
        log.debug("method: {method}, url: {url}, params: {params}",
            method="GET",
            url=url,
            params=params)
        resp = yield self.make_authenticated_api_call(
            "GET",
            url,
            headers=headers,
            params=params)
        resp_code = resp.code
        parsed = yield resp.json()
        log.debug("Result of fetch attempt: {parsed}", parsed=parsed)
        if resp_code not in (200,):
            raise Exception("API call to fetch remote account ID returned HTTP status {}".format(resp_code))
        data = parsed.get("data", None)
        if data is None:
            log.debug("No `data` element in parsed response.")
            returnValue(None)
        users = data.get("users", [])
        if len(users) == 0:
            log.debug("Empty/no `users` element in parsed response.")
            returnValue(None)
        user = users[0]
        api_id = user.get("userId", None)
        if api_id is None:
            log.debug("No `userId` attribute in parsed response.")
        returnValue(api_id)

    @inlineCallbacks
    def api_update_subject(self, subject, api_id, attributes):
        """
        Make API request to update remote account.
        Returns the HTTP response.
        """
        log = self.log
        log.debug("entered api_update_subject()")
        resp_code = yield self.change_subject_status_(api_id, active=True)
        if resp_code != 204:
            raise Exception("API call to activate subject returned HTTP status {}".format(resp_code))
        prefix = self.url_prefix
        url = "{}/api/User/{}".format(prefix, api_id)
        headers = {
            'Accept': ['application/json'],
            'Content-Type': ['application/json'],
        }
        surname = attributes.get("sn", [""])[0]
        givenname = attributes.get("givenName", [""])[0]
        props = {
            'firstName': givenname,
            'lastName': surname,
        }
        serialized = json.dumps(props)
        body = StringProducer(serialized.encode('utf-8'))
        log.debug("url: {url}", url=url)
        log.debug("headers: {headers}", headers=headers)
        log.debug("body: {body}", body=serialized)
        resp = yield self.make_authenticated_api_call(
            'PUT',  
            url, 
            data=body, 
            headers=headers)
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
        log.debug("Entered: api_add_subject().")
        api_id = yield self.fetch_account_id(subject, attributes)
        if api_id:
            resp_code = yield self.change_subject_status_(api_id, active=True)
            if resp_code != 204:
                raise Exception("API call to activate subject returned HTTP status {}".format(resp_code))
            returnValue(api_id)

class CrashplanProvisionerFactory(RESTProvisionerFactory):
    tag = "crashplan_provisioner"
    opt_help = "Code42 CrashPlan API Provisioner"
    opt_usage = "This plugin does not support any options."
    provisioner_factory = CrashplanProvisioner


