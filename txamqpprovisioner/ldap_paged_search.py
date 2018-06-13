
from __future__ import print_function
from twisted.internet import defer
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from ldaptor.protocols import pureber

@defer.inlineCallbacks
def paged_search(client, page_size, callback, basedn, **search_kwds):
    """
    Performs a search using the LDAP paged search control, requesting
    pages of size `page_size`.  When a page of results is available,
    `callback` is called with arguments (page, results).
    """
    cookie = ''
    page = 1
    while True:
        results, cookie = yield request_page_(
            client, 
            basedn, 
            page_size=page_size,
            cookie=cookie,
            **search_kwds)
        callback((page, results))
        if len(cookie) == 0:
            break
        page += 1

@defer.inlineCallbacks
def request_page_(client, basedn, page_size=100, cookie='', **search_kwds):
    control_value = pureber.BERSequence([
        pureber.BERInteger(page_size),
        pureber.BEROctetString(cookie),
    ])
    controls = [('1.2.840.113556.1.4.319', None, control_value)]
    search_kwds['controls'] = controls
    search_kwds['return_controls'] = True
    o = LDAPEntry(client, basedn)
    results, resp_controls  = yield o.search(**search_kwds)
    cookie = get_paged_search_cookie_(resp_controls)
    defer.returnValue((results, cookie))

def get_paged_search_cookie_(controls):
    """
    Input: semi-parsed controls list from LDAP response; list of tuples (controlType, criticality, controlValue).
    Parses the controlValue and returns the cookie as a byte string.
    """
    control_value = controls[0][2]
    ber_context = pureber.BERDecoderContext()
    ber_seq, bytes_used = pureber.berDecodeObject(ber_context, control_value)
    raw_cookie = ber_seq[1]
    cookie = raw_cookie.value
    return cookie 
