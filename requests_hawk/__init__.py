# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import hashlib
import hmac
import math
from urlparse import urlparse

import mohawk
from requests.auth import AuthBase


class HawkAuth(AuthBase):
    """Handles authentication using Hawk.

    :param hawk_session:
      The hawk session, from the server, encoded as hexadecimal.
      You don't need to set this parameter if you already know the hawk
      credentials (Optional).

    :param credentials:
      Python dict containing credentials information, with keys for "id",
      "key" and "algorithm" (Optional).

    :param server_url:
      The url of the server, this is useful for hawk when signing the requests.
      In case this is omited, fallbacks to the value of the "Host" header of
      the request (Optional).


    Note that the `hawk_session` and `credentials` parameters are mutually
    exclusive.  You should set one or the other.

    """
    def __init__(self, hawk_session=None, credentials=None, server_url=None):
        if ((credentials, hawk_session) == (None, None)
                or (credentials is not None and hawk_session is not None)):
            raise AttributeError("You should pass either 'hawk_session' "
                                 "or 'credentials'.")

        elif hawk_session is not None:
            hawk_session = hawk_session.decode('hex')
            keyInfo = 'identity.mozilla.com/picl/v1/sessionToken'
            keyMaterial = HKDF(hawk_session, "", keyInfo, 32*3)
            credentials = {
                'id': keyMaterial[:32].encode("hex"),
                'key': keyMaterial[32:64].encode("hex"),
                'algorithm': 'sha256'
            }
        self.credentials = credentials

        if server_url is not None:
            self.host = urlparse(self.server_url).netloc
        else:
            self.host = None

    def __call__(self, r):
        if self.host is not None:
            r.headers['Host'] = self.host

        sender = mohawk.Sender(
            self.credentials,
            r.url,
            r.method,
            content=r.body or '',
            content_type=r.headers.get('Content-Type', '')
        )

        r.headers['Authorization'] = sender.request_header
        return r


def HKDF_extract(salt, IKM, hashmod=hashlib.sha256):
    """HKDF-Extract; see RFC-5869 for the details."""
    if salt is None:
        salt = b"\x00" * hashmod().digest_size
    return hmac.new(salt, IKM, hashmod).digest()


def HKDF_expand(PRK, info, L, hashmod=hashlib.sha256):
    """HKDF-Expand; see RFC-5869 for the details."""
    digest_size = hashmod().digest_size
    N = int(math.ceil(L * 1.0 / digest_size))
    assert N <= 255
    T = b""
    output = []
    for i in xrange(1, N + 1):
        data = T + info + chr(i)
        T = hmac.new(PRK, data, hashmod).digest()
        output.append(T)
    return b"".join(output)[:L]


def HKDF(secret, salt, info, size, hashmod=hashlib.sha256):
    """HKDF-extract-and-expand as a single function."""
    PRK = HKDF_extract(salt, secret, hashmod)
    return HKDF_expand(PRK, info, size, hashmod)
