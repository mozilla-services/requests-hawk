import binascii
import codecs
import hashlib
import hmac
import math
from six.moves import xrange
from six.moves.urllib.parse import urlparse
from six import text_type

import mohawk
from mohawk.base import EmptyValue
from requests.auth import AuthBase


class HawkAuth(AuthBase):
    """Handles authentication using Hawk.

    :param hawk_session:
      The hawk session, from the server, encoded as hexadecimal.
      You don't need to set this parameter if you already know the hawk
      credentials (Optional).

    :param id:
      The hawk id string to use for authentication (Optional).

    :param key:
      A string containing the hawk secret key (Optional).

    :param algorithm:
      A string containing the name of the algorithm to be used.
      (Optional, defaults to 'sha256').

    :param server_url:
      The url of the server, this is useful for hawk when signing the requests.
      In case this is omitted, fallbacks to the value of the "Host" header of
      the request (Optional).

    :param ext:
      A string of arbitrary data to be sent along with the request (Optional).

    Note that the `hawk_session` and `id` parameters are mutually exclusive.
    You should use either `hawk_session` or both `id` and 'key'.
    """
    def __init__(self, hawk_session=None, id=None, key=None, algorithm='sha256',
                 credentials=None, server_url=None, _timestamp=None,
                 always_hash_content=True, ext=None, app=None):
        if credentials is not None:
            raise AttributeError("The 'credentials' param has been removed. "
                                 "Pass 'id' and 'key' instead, or '**credentials_dict'.")

        if (hawk_session and (id or key)
                or not hawk_session and not (id and key)):
            raise AttributeError("You should pass either 'hawk_session' "
                                 "or both 'id' and 'key'.")

        if hawk_session:
            try:
                hawk_session = codecs.decode(hawk_session, 'hex_codec')
            except binascii.Error as e:
                raise TypeError(e)
            keyInfo = 'identity.mozilla.com/picl/v1/sessionToken'
            keyMaterial = HKDF(hawk_session, "", keyInfo, 32*2)
            id = codecs.encode(keyMaterial[:32], "hex_codec")
            key = codecs.encode(keyMaterial[32:64], "hex_codec")

        self.credentials = {
            'id': id,
            'key': key,
            'algorithm': algorithm
        }
        self._timestamp = _timestamp
        self.host = urlparse(server_url).netloc if server_url else None
        self.always_hash_content = always_hash_content
        self.ext = ext
        self.app = app

    def __call__(self, r):
        if self.host is not None:
            r.headers['Host'] = self.host

        content_type = r.headers.get("Content-Type") or ""
        if not isinstance(content_type, text_type):
            content_type = content_type.decode("utf-8")

        sender = mohawk.Sender(
            self.credentials,
            r.url,
            r.method,
            content=r.body or EmptyValue,
            content_type=content_type or EmptyValue,
            always_hash_content=self.always_hash_content,
            _timestamp=self._timestamp,
            ext=self.ext,
            app=self.app
        )

        r.headers['Authorization'] = sender.request_header
        return r


def HKDF_extract(salt, IKM, hashmod=hashlib.sha256):
    """HKDF-Extract; see RFC-5869 for the details."""
    if salt is None:
        salt = b"\x00" * hashmod().digest_size
    if isinstance(salt, text_type):
        salt = salt.encode("utf-8")
    return hmac.new(salt, IKM, hashmod).digest()


def HKDF_expand(PRK, info, L, hashmod=hashlib.sha256):
    """HKDF-Expand; see RFC-5869 for the details."""
    if isinstance(info, text_type):
        info = info.encode("utf-8")
    digest_size = hashmod().digest_size
    N = int(math.ceil(L * 1.0 / digest_size))
    assert N <= 255
    T = b""
    output = []
    for i in xrange(1, N + 1):
        data = T + info + chr(i).encode("utf-8")
        T = hmac.new(PRK, data, hashmod).digest()
        output.append(T)
    return b"".join(output)[:L]


def HKDF(secret, salt, info, size, hashmod=hashlib.sha256):
    """HKDF-extract-and-expand as a single function."""
    PRK = HKDF_extract(salt, secret, hashmod)
    return HKDF_expand(PRK, info, size, hashmod)


# If httpie is installed, register the hawk plugin.
try:

    from httpie.plugins import AuthPlugin

    class HawkPlugin(AuthPlugin):

        name = 'Hawk Auth'
        auth_type = 'hawk'
        description = ''

        def get_auth(self, username, password):
            if password == '':
                return HawkAuth(hawk_session=username)
            return HawkAuth(id=username, key=password)

except ImportError:
    pass
