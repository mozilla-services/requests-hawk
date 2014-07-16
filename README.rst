Requests-Hawk
#############

This project allows you to use `the python requests library
<http://python-requests.org/>`_ with `the hawk authentication
<https://github.com/hueniverse/hawk>`_ mechanism.

Hawk itself does not provide any mechanism for obtaining or transmitting the
set of shared credentials required, but this project proposes the following
scheme:

The server gives you a session token, that you'll need to derive to get the
hawk credentials:

Do an HKDF derivation on the given session token. You’ll need to use the
following parameters::

    key_material = HKDF(hawk_session, “”, ‘identity.mozilla.com/picl/v1/sessionToken’, 32*3)

The key material you’ll get out of the HKDF need to be separated into two
parts, the first 32 hex caracters are the hawk id, and the next 32 ones are the
hawk key::

    credentials = {
        'id': keyMaterial[0:32]
        'key': keyMaterial[32:64]
        'algorithm': 'sha256'
    }


Great, how can I use it?
========================

First, you'll need to install it::

    pip install requests-hawk

Then, in your project, you can use it like that::

    import requests
    from requests_hawk import HawkAuth

    hawk_auth = HawkAuth(
        hawk_session=resp.headers['hawk-session-token'],
        server_url=self.server_url
    )
    requests.post("/url", auth=hawk_auth)
