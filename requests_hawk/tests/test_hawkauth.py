import codecs
import unittest
from requests import Request
from requests_hawk import HawkAuth


class TestHawkAuth(unittest.TestCase):

    def test_hawkauth_errors_when_id_and_key_and_hawk_session_passed(self):
        self.assertRaises(AttributeError, HawkAuth,
                          id='test', key='test', hawk_session="test")

    def test_hawkauth_errors_when_id_and_hawk_session_passed(self):
        self.assertRaises(AttributeError, HawkAuth,
                          id='test', hawk_session="test")

    def test_hawkauth_errors_when_key_and_hawk_session_passed(self):
        self.assertRaises(AttributeError, HawkAuth,
                          key='test', hawk_session="test")

    def test_hawkauth_errors_when_only_id_passed(self):
        self.assertRaises(AttributeError, HawkAuth, id='test')

    def test_hawkauth_errors_when_only_key_passed(self):
        self.assertRaises(AttributeError, HawkAuth, key='test')

    def test_hawkauth_errors_when_credentials_passed(self):
        self.assertRaises(AttributeError, HawkAuth, credentials={})

    def test_hawkauth_errors_when_no_auth_is_set(self):
        self.assertRaises(AttributeError, HawkAuth)

    def test_hawk_auth_supports_credentials_as_parameters(self):
        auth = HawkAuth(id='test_id', key='test_key', _timestamp=1431698426)
        request = Request('PUT', 'http://www.example.com',
                          json={"foo": "bar"}, auth=auth)
        r = request.prepare()
        auth_header = r.headers['Authorization']
        self.assertTrue('id="test_id"' in auth_header, "ID doesn't match")
        self.assertTrue('hash="lby/vvNtW9J/ZI39Nnfcrl2ESgx8JIIZ/SaIvfd3iaQ="'
                        in auth_header,
                        "Hash doesn't match")
        self.assertTrue('ts="1431698426"' in auth_header,
                        "Timestamp doesn't match")
        self.assertEqual(r.body, b'{"foo": "bar"}')

    def test_overriding_credentials_algorithm(self):
        auth = HawkAuth(id='test_id', key='test_key', algorithm='sha1')
        self.assertEqual(auth.credentials['algorithm'], 'sha1')

    def test_key_non_hex_values_throws(self):
        self.assertRaises(TypeError, HawkAuth, hawk_session="test")

    def test_credentials_are_derived_from_session(self):
        auth = HawkAuth(hawk_session=codecs.encode(b"hello", "hex_codec"))
        self.assertEqual(auth.credentials, {
            'id': b'15064c77e946608226a9c2d8da61ac5e0e85f325334965c68a3f47e809'
                  b'1f8412',
            'key': b'cb3829c6d6fe3f58609d58f09818295dfbdf45803ec50b8d66c4132f7'
                   b'ad14aa0',
            'algorithm': 'sha256'
        })

    def test_overriding_session_algorithm(self):
        auth = HawkAuth(hawk_session=codecs.encode(b"hello", "hex_codec"),
                        algorithm='sha1')
        self.assertEqual(auth.credentials['algorithm'], 'sha1')

    def test_server_url_is_parsed(self):
        auth = HawkAuth(hawk_session=codecs.encode(b"hello", "hex_codec"),
                        server_url="http://localhost:5000")
        self.assertEquals(auth.host, "localhost:5000")

    def test_hawk_auth_can_handle_a_timestamp_argument(self):
        auth = HawkAuth(hawk_session=codecs.encode(b"hello", "hex_codec"),
                        _timestamp=1431698847)

        request = Request('PUT', 'http://www.example.com',
                          {'Content-Type': 'application/json'},
                          data='{"foo": "bar"}', auth=auth)

        r = request.prepare()
        self.assertTrue('ts="1431698847"' in r.headers['Authorization'],
                        "Timestamp doesn't match")
        self.assertEqual(r.body, '{"foo": "bar"}')

    def test_hawk_auth_is_called_when_json_present(self):
        auth = HawkAuth(hawk_session=codecs.encode(b"hello", "hex_codec"),
                        _timestamp=1431698847)

        request = Request('PUT', 'http://www.example.com',
                          json={"foo": "bar"}, auth=auth)
        r = request.prepare()

        self.assertTrue('ts="1431698847"' in r.headers['Authorization'],
                        "Timestamp doesn't match")
        self.assertEqual(r.body, b'{"foo": "bar"}')

    def test_hawk_auth_supports_empty_body(self):
        auth = HawkAuth(id='test_id', key='test_key', always_hash_content=False)
        request = Request('GET', 'http://www.example.com', auth=auth)
        r = request.prepare()
        self.assertNotIn('hash="', r.headers['Authorization'])

    def test_hawk_auth_supports_binary_content_type(self):
        headers = {'Content-Type': b'application/json'}
        auth = HawkAuth(id='test_id', key='test_key')
        request = Request('POST', 'https://example.com', auth=auth,
                          headers=headers, data=b"data")
        r = request.prepare()
        auth_header = r.headers['Authorization']
        self.assertTrue('id="test_id"' in auth_header, "ID doesn't match")
