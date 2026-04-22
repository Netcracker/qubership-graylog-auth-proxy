import unittest
from unittest.mock import MagicMock, patch, mock_open
from urllib.parse import urlparse

import common.session as session
import common.vars as common_vars
from config.common_config import CommonConfig
from config.graylog import GraylogConfig
from config.oauth import OAuthConfig
from config.ldap import LDAPConfig
from oauth_handler.handler import OAuthHandler
from ldap_auth_handler.handler import LDAPAuthHandler


class TestHeaderHandling(unittest.TestCase):
    def setUp(self):
        # Reset session storage before each test
        session.sessions.clear()

        # Setup common configuration
        self.common_config = CommonConfig(
            cookie_name="test_cookie",
            port=8888,
            metrics_port=8889,
            tls_enabled="false",
            cert_path="",
            key_path="",
            host="test_proxy"
        )

        # Setup OAuth configuration
        self.oauth_config = OAuthConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            host="https://test-auth.com",
            authorization_path="/auth",
            token_path="/token",
            userinfo_path="/userinfo",
            redirect_uri="https://test-redirect.com/callback",
            scopes="test_scope",
            insecure_skip_verify="true",
            user_jsonpath="preferred_username",
            roles_jsonpath="realm_access.roles[*]",
            requests_timeout=30,
            ca_cert_path=None,
            cert_path=None,
            key_path=None,
            htpasswd=None
        )

        # Setup LDAP configuration
        self.ldap_config = LDAPConfig(
            url="ldap://test-ldap.com",
            starttls="false",
            over_ssl="false",
            ca_cert_path=None,
            cert_path=None,
            key_path=None,
            insecure_skip_verify="true",
            disable_referrals="false",
            basedn="dc=test,dc=com",
            filter="(uid={})",
            binddn="cn=admin,dc=test,dc=com",
            plain_password="test_password",
            htpasswd=None,
            realm="test",
            requests_timeout=30
        )

        # Setup Graylog configuration
        self.graylog_config = GraylogConfig(
            host="test.graylog.com",
            admin_user="test_user",
            insecure_skip_verify="true",
            requests_timeout=30,
            ca_cert_path=None,
            key_path=None,
            cert_path=None,
            pre_created_users="admin,auditViewer,operator",
            role_mapping="[]",
            stream_mapping=""
        )

        # Create mock request objects
        self.create_mock_request()

    def create_mock_request(self):
        """Create mock request objects for both handlers"""
        class MockSocket:
            def sendall(self, data):
                pass

            def makefile(self, mode, bufsize):
                if mode == 'rb':
                    mock_file = MagicMock()
                    mock_file.readline.return_value = b"GET / HTTP/1.1\r\n"
                    return mock_file
                return MagicMock()

        class MockConnection:
            def __init__(self):
                self.sock = MockSocket()

            def makefile(self, mode, bufsize):
                return self.sock.makefile(mode, bufsize)

            def sendall(self, data):
                return self.sock.sendall(data)

        class MockRequest:
            def __init__(self):
                self.connection = MockConnection()
                self.rfile = self.connection.makefile('rb', -1)
                self.wfile = self.connection.makefile('wb', 0)
                self.headers = {}
                self._sock = self.connection.sock
                self.makefile = self.connection.makefile
                self.sendall = self.connection.sendall

        mock_request = MockRequest()
        mock_server = MagicMock()

        # Setup OAuth handler
        self.oauth_handler = OAuthHandler(mock_request, ("", 0), mock_server)
        self.oauth_handler.rfile = mock_request.rfile
        self.oauth_handler.wfile = mock_request.wfile
        self.oauth_handler.request = mock_request
        self.oauth_handler.client_address = ("127.0.0.1", 12345)
        self.oauth_handler.server = mock_server
        self.oauth_handler.connection = mock_request.connection
        self.oauth_handler.parse_request()
        self.oauth_handler.headers = {}
        self.oauth_handler.set_common_params(self.common_config)
        self.oauth_handler.set_auth_params(self.oauth_config)
        self.oauth_handler.set_graylog_params(self.graylog_config)

        # Setup LDAP handler
        self.ldap_handler = LDAPAuthHandler(mock_request, ("", 0), mock_server)
        self.ldap_handler.rfile = mock_request.rfile
        self.ldap_handler.wfile = mock_request.wfile
        self.ldap_handler.request = mock_request
        self.ldap_handler.client_address = ("127.0.0.1", 12345)
        self.ldap_handler.server = mock_server
        self.ldap_handler.connection = mock_request.connection
        self.ldap_handler.parse_request()
        self.ldap_handler.headers = {}
        self.ldap_handler.set_common_params(self.common_config)
        self.ldap_handler.set_auth_params(self.ldap_config)
        self.ldap_handler.set_graylog_params(self.graylog_config)

    def test_csp_header_modification_oauth(self):
        """Test that CSP headers are properly modified for OAuth"""
        # Create mock response with CSP header
        mock_response = MagicMock()
        mock_response.headers = {
            'Content-Security-Policy': "connect-src 'self' https://graylog.org/post/tag/ https://telemetry.graylog.cloud"
        }
        mock_response.content = b"test content"

        # Mock the send_header method to capture what headers are sent
        sent_headers = {}
        original_send_header = self.oauth_handler.send_header

        def mock_send_header(name, value):
            sent_headers[name] = value

        self.oauth_handler.send_header = mock_send_header

        # Call send_resp_headers
        self.oauth_handler.send_resp_headers(mock_response)

        # Verify CSP header was modified to include OAuth domain
        self.assertIn('Content-Security-Policy', sent_headers)
        csp_value = sent_headers['Content-Security-Policy']
        self.assertIn('https://test-auth.com', csp_value)
        self.assertIn(
            "connect-src 'self' https://graylog.org/post/tag/ https://telemetry.graylog.cloud https://test-auth.com", csp_value)

    def test_csp_header_preservation_ldap(self):
        """Test that CSP headers are preserved as-is for LDAP"""
        # Create mock response with CSP header
        mock_response = MagicMock()
        original_csp = "connect-src 'self' https://graylog.org/post/tag/ https://telemetry.graylog.cloud"
        mock_response.headers = {
            'Content-Security-Policy': original_csp
        }
        mock_response.content = b"test content"

        # Mock the send_header method to capture what headers are sent
        sent_headers = {}
        original_send_header = self.ldap_handler.send_header

        def mock_send_header(name, value):
            sent_headers[name] = value

        self.ldap_handler.send_header = mock_send_header

        # Call send_resp_headers
        self.ldap_handler.send_resp_headers(mock_response)

        # Verify CSP header was preserved unchanged
        self.assertIn('Content-Security-Policy', sent_headers)
        self.assertEqual(sent_headers['Content-Security-Policy'], original_csp)

    def test_csp_header_without_connect_src(self):
        """Test CSP header handling when connect-src is not present"""
        # Create mock response with CSP header without connect-src
        mock_response = MagicMock()
        mock_response.headers = {
            'Content-Security-Policy': "default-src 'self'; script-src 'self'"
        }
        mock_response.content = b"test content"

        # Mock the send_header method to capture what headers are sent
        sent_headers = {}
        original_send_header = self.oauth_handler.send_header

        def mock_send_header(name, value):
            sent_headers[name] = value

        self.oauth_handler.send_header = mock_send_header

        # Call send_resp_headers
        self.oauth_handler.send_resp_headers(mock_response)

        # Verify CSP header was preserved unchanged (no connect-src to modify)
        self.assertIn('Content-Security-Policy', sent_headers)
        self.assertEqual(sent_headers['Content-Security-Policy'], "default-src 'self'; script-src 'self'")

    def test_content_length_preservation(self):
        """Test that original Content-Length headers are preserved"""
        # Create mock response with Content-Length
        mock_response = MagicMock()
        mock_response.headers = {
            'Content-Length': '1234',
            'Content-Type': 'text/html'
        }
        mock_response.content = b"test content"

        # Mock the send_header method to capture what headers are sent
        sent_headers = {}
        original_send_header = self.oauth_handler.send_header

        def mock_send_header(name, value):
            sent_headers[name] = value

        self.oauth_handler.send_header = mock_send_header

        # Call send_resp_headers
        self.oauth_handler.send_resp_headers(mock_response)

        # Verify original Content-Length was preserved
        self.assertIn('Content-Length', sent_headers)
        self.assertEqual(sent_headers['Content-Length'], '1234')

    def test_content_length_addition_when_missing(self):
        """Test that Content-Length is added when missing from original response"""
        # Create mock response without Content-Length
        mock_response = MagicMock()
        mock_response.headers = {
            'Content-Type': 'text/html'
        }
        mock_response.content = b"test content"

        # Mock the send_header method to capture what headers are sent
        sent_headers = {}
        original_send_header = self.oauth_handler.send_header

        def mock_send_header(name, value):
            sent_headers[name] = value

        self.oauth_handler.send_header = mock_send_header

        # Call send_resp_headers
        self.oauth_handler.send_resp_headers(mock_response)

        # Verify Content-Length was added
        self.assertIn('Content-Length', sent_headers)
        self.assertEqual(sent_headers['Content-Length'], '12')  # len(b"test content")

    def test_chunked_transfer_encoding(self):
        """Test that Content-Length is not added for chunked transfer encoding"""
        # Create mock response with chunked transfer encoding
        mock_response = MagicMock()
        mock_response.headers = {
            'Transfer-Encoding': 'chunked',
            'Content-Type': 'text/html'
        }
        mock_response.content = b"test content"

        # Mock the send_header method to capture what headers are sent
        sent_headers = {}
        original_send_header = self.oauth_handler.send_header

        def mock_send_header(name, value):
            sent_headers[name] = value

        self.oauth_handler.send_header = mock_send_header

        # Call send_resp_headers
        self.oauth_handler.send_resp_headers(mock_response)

        # Verify Content-Length was NOT added for chunked transfer
        self.assertNotIn('Content-Length', sent_headers)

    def test_binary_content_handling(self):
        """Test that binary content is handled correctly without text encoding"""
        # Create mock response with binary content
        mock_response = MagicMock()
        binary_content = b'\x00\x01\x02\x03\x04\x05'  # Binary data
        mock_response.content = binary_content
        mock_response.headers = {
            'Content-Type': 'application/octet-stream'
        }

        # Mock the wfile.write method to capture what's written
        written_content = []
        original_write = self.oauth_handler.wfile.write

        def mock_write(data):
            written_content.append(data)

        self.oauth_handler.wfile.write = mock_write

        # Mock the send_resp_headers method to avoid header processing
        original_send_resp_headers = self.oauth_handler.send_resp_headers

        def mock_send_resp_headers(resp):
            pass

        self.oauth_handler.send_resp_headers = mock_send_resp_headers

        # Simulate writing content (as done in do_GET)
        self.oauth_handler.wfile.write(mock_response.content)

        # Verify binary content was written without corruption
        self.assertEqual(len(written_content), 1)
        self.assertEqual(written_content[0], binary_content)

    def test_csp_header_case_insensitive(self):
        """Test that CSP header detection is case insensitive"""
        # Create mock response with CSP header in different cases
        mock_response = MagicMock()
        mock_response.headers = {
            'content-security-policy': "connect-src 'self' https://graylog.org/post/tag/ https://telemetry.graylog.cloud"
        }
        mock_response.content = b"test content"

        # Mock the send_header method to capture what headers are sent
        sent_headers = {}
        original_send_header = self.oauth_handler.send_header

        def mock_send_header(name, value):
            sent_headers[name] = value

        self.oauth_handler.send_header = mock_send_header

        # Call send_resp_headers
        self.oauth_handler.send_resp_headers(mock_response)

        # Verify CSP header was modified despite different case
        self.assertIn('content-security-policy', sent_headers)
        csp_value = sent_headers['content-security-policy']
        self.assertIn('https://test-auth.com', csp_value)

    def test_multiple_oauth_domains_in_csp(self):
        """Test that multiple OAuth domains can be added to CSP"""
        # Create mock response with CSP header
        mock_response = MagicMock()
        mock_response.headers = {
            'Content-Security-Policy': "connect-src 'self' https://graylog.org/post/tag/"
        }
        mock_response.content = b"test content"

        # Mock the send_header method to capture what headers are sent
        sent_headers = {}
        original_send_header = self.oauth_handler.send_header

        def mock_send_header(name, value):
            sent_headers[name] = value

        self.oauth_handler.send_header = mock_send_header

        # Call send_resp_headers multiple times to simulate multiple domains
        self.oauth_handler.send_resp_headers(mock_response)
        self.oauth_handler.send_resp_headers(mock_response)

        # Verify OAuth domain was added only once (no duplicates)
        self.assertIn('Content-Security-Policy', sent_headers)
        csp_value = sent_headers['Content-Security-Policy']
        oauth_domain_count = csp_value.count('https://test-auth.com')
        self.assertEqual(oauth_domain_count, 1)


if __name__ == '__main__':
    unittest.main()
