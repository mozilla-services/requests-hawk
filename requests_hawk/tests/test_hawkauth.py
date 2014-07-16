from requests_hawk import HawkAuth
import unittest


class TestHawkAuth(unittest.TestCase):

    def test_hawkauth_errors_when_credentials_and_hawk_session_passed(self):
        self.assertRaise(AttributeError, HawkAuth,
                         credentials={}, hawk_session="test")
