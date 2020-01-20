Requests-Hawk
#############

|pypi| |travis|

.. |travis| image:: https://travis-ci.org/mozilla-services/requests-hawk.png
    :target: https://travis-ci.org/mozilla-services/requests-hawk

.. |pypi| image:: https://img.shields.io/pypi/v/requests-hawk.svg
    :target: https://pypi.python.org/pypi/requests-hawk


This project allows you to use `the python requests library
<http://python-requests.org/>`_ with `the hawk authentication
<https://github.com/hueniverse/hawk>`_ mechanism.

Hawk itself does not provide any mechanism for obtaining or transmitting the
set of shared credentials required, but this project proposes a scheme we use
across mozilla services projects.

Great, how can I use it?
========================

First, you'll need to install it:

.. code-block:: bash

    pip install requests-hawk

Then, in your project, if you know the `id` and `key`, you can use:

.. code-block:: python

    import requests
    from requests_hawk import HawkAuth

    hawk_auth = HawkAuth(id='my-hawk-id', key='my-hawk-secret-key')
    requests.post("https://example.com/url", auth=hawk_auth)

Or if you need to derive them from the hawk session token, instead use:

.. code-block:: python

    import requests
    from requests_hawk import HawkAuth

    hawk_auth = HawkAuth(
        hawk_session=resp.headers['hawk-session-token'],
        server_url=self.server_url
    )
    requests.post("/url", auth=hawk_auth)

In the second example, the ``server_url`` parameter to ``HawkAuth`` was used to
provide a default host name, to avoid having to repeat it for each request.

If you wish to override the default algorithm of ``sha256``, pass the desired
algorithm name using the optional ``algorithm`` parameter.

Note: The ``credentials`` parameter has been removed. Instead pass ``id`` and
``key`` separately (as above), or pass the existing dict as ``**credentials``.

Integration with httpie
=======================

`Httpie <https://github.com/jakubroztocil/httpie>`_ is a tool which lets you do
requests to a distant server in a nice and easy way. Under the hood, ``httpie``
uses the requests library. We've made it simple for you to plug hawk with it.

If you know the id and key, use it like that:

.. code-block:: bash

   http POST localhost:5000/registration\
   --auth-type=hawk --auth='id:key'

Or, if you want to use the hawk session token, you can do as follows:

.. code-block:: bash

   http POST localhost:5000/registration\
   --auth-type=hawk --auth='c0d8cd2ec579a3599bef60f060412f01f5dc46f90465f42b5c47467481315f51:'

Take care, don't forget to add the extra ``:`` at the end of the hawk session
token for it to be considered like so.

How are the shared credentials shared?
======================================

Okay, on to the actual details.

The server gives you a session token, that you'll need to derive to get the
hawk credentials.

Do an HKDF derivation on the given session token. You'll need to use the
following parameters:

.. code-block:: python

    key_material = HKDF(hawk_session, '', 'identity.mozilla.com/picl/v1/sessionToken', 32*2)

The key material you'll get out of the HKDF needs to be separated into two
parts, the first 32 hex characters are the ``hawk id``, and the next 32 ones are the
``hawk key``:

.. code-block:: python

    credentials = {
        'id': keyMaterial[0:32]
        'key': keyMaterial[32:64]
        'algorithm': 'sha256'
    }

Run tests
=========

To run test, you can use tox:

.. code-block:: bash

    tox
