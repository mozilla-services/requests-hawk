Requests-Hawk
#############

This project allows you to use `the python requests library
<http://python-requests.org/>`_ with `the hawk authentication
<https://github.com/hueniverse/hawk>`_ mechanism.

Hawk itself does not provide any mechanism for obtaining or transmitting the
set of shared credentials required, but this project proposes the following
scheme (that we use accross mozilla services projects).

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

Integration with httpie
=======================

`Httpie <https://github.com/jakubroztocil/httpie>`_ is a tool which lets you do
requests to a distant server in a nice and easy way. Under the hood, httpie
uses the requests library. We've made it simple for you to plug hawk with it::

   http POST localhost:5000/registration simple_push_url=https://test --verbose\
   --auth-type=hawk --auth='c0d8cd2ec579a3599bef60f060412f01f5dc46f90465f42b5c47467481315f51:'

Take care, don't forgot to add the extra `:` at the end of the hawk session
token.

How are the shared credentials shared?
======================================

Okay, on to the actual details.

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

