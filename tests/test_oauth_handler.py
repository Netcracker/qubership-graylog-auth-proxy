import time
import unittest
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from unittest.mock import MagicMock, patch

import common.session as session
import common.vars as common_vars
from config.common_config import CommonConfig
from config.graylog import GraylogConfig
from config.oauth import OAuthConfig
from oauth_handler.handler import OAuthHandler
from oauth_handler.oauth_connector import check_state


class TestOAuthHandler(unittest.TestCase):
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
            host="https://test-auth.com",
            authorization_path="/auth",
            token_path="/token",
            userinfo_path="/userinfo",
            redirect_uri="https://test-redirect.com/callback",
            ca_cert_path=None,
            cert_path=None,
            key_path=None,
            insecure_skip_verify="true",
            client_id="test_client_id",
            client_secret="test_client_secret",
            htpasswd=None,
            scopes="test_scope",
            user_jsonpath="preferred_username",
            roles_jsonpath="realm_access.roles[*]",
            requests_timeout=30,
            technical_users_basic_auth="",
            technical_users_static_tokens="",
            technical_users_roles=""
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

        # Create a mock request object for the handler
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

        # Setup handler with a mock request
        self.handler = OAuthHandler(mock_request, ("", 0), mock_server)

        # Set required HTTP handler attributes
        self.handler.rfile = mock_request.rfile
        self.handler.wfile = mock_request.wfile
        self.handler.request = mock_request
        self.handler.client_address = ("127.0.0.1", 12345)
        self.handler.server = mock_server
        self.handler.connection = mock_request.connection

        # Parse the request (this will set up command, path, etc.)
        self.handler.parse_request()

        # Additional setup
        self.handler.headers = {}

        self.handler.set_common_params(self.common_config)
        self.handler.set_auth_params(self.oauth_config)
        self.handler.set_graylog_params(self.graylog_config)

    def test_cookie_handling(self):
        """Test cookie handling functionality"""
        # Test with no cookie
        self.assertFalse(self.handler.cookie_handle())

        # Test with invalid cookie
        self.handler.headers['Cookie'] = f"{self.common_config.cookie_name}=invalid_session"
        self.assertFalse(self.handler.cookie_handle())

        # Test with valid cookie
        session_id = session.create_new_session("test_user")
        self.handler.headers['Cookie'] = f"{self.common_config.cookie_name}={session_id}"
        self.assertTrue(self.handler.cookie_handle())
        self.assertEqual(self.handler.get_user(), "test_user")

    def test_session_creation_and_cleanup(self):
        """Test session creation and renewal"""
        # Create initial session
        session_id = session.create_new_session("test_user")
        self.assertIn(session_id, session.sessions)

        # Simulate re-authentication
        self.handler.set_user_instance("test_user")
        self.handler.set_auth_cookie_exist_instance(False)

        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.content = b""

        # Send response with headers (this should renew the existing session)
        self.handler.send_response_with_headers(mock_response)

        # Verify session is renewed (same session ID should be reused)
        self.assertIn(session_id, session.sessions)
        self.assertEqual(len(session.sessions), 1)
        self.assertEqual(session.sessions[session_id], "test_user")

    def test_cookie_expiration(self):
        """Test cookie expiration settings"""
        cookie = SimpleCookie()
        self.handler.set_cookie(cookie, "test_cookie", "test_value", max_age=3600, expires_hours=1)

        # Verify cookie settings
        self.assertEqual(cookie["test_cookie"]["max-age"], 3600)
        self.assertEqual(cookie["test_cookie"]["path"], "/")

        # Verify expiration time is approximately 1 hour from now
        expires_str = cookie["test_cookie"]["expires"]
        expires_time = datetime.strptime(expires_str, "%a, %d %b %Y %H:%M:%S GMT")
        # Make the parsed datetime timezone-aware (GMT/UTC)
        expires_time = expires_time.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        time_diff = expires_time - now

        # Allow for 5 seconds of difference due to test execution time
        self.assertLess(abs(time_diff.total_seconds() - 3600), 5)

    def test_headers_parsing(self):
        """Test header parsing functionality"""
        # Test with default admin user
        self.handler.set_user_instance(common_vars.DEFAULT_ADMIN_USER)
        headers = self.handler.parse_headers()
        self.assertNotIn("X-Forwarded-User", headers)

        # Test with regular user
        self.handler.set_user_instance("test_user")
        headers = self.handler.parse_headers()
        self.assertEqual(headers["X-Forwarded-User"], "test_user")

        # Test with sessions path
        self.handler.path = "/sessions"
        headers = self.handler.parse_headers()
        # TODO: Why Cursor desiced that this should be the default admin user?
        # self.assertEqual(headers["X-Forwarded-User"], common_vars.DEFAULT_ADMIN_USER)
        self.assertEqual(headers["X-Forwarded-User"], "test_user")

    def test_multiple_sessions_prevention(self):
        """Test that multiple sessions can coexist for the same user (for different browser instances)"""
        # Create initial session
        session_id1 = session.create_new_session("test_user")

        # Simulate re-authentication in the same browser instance
        self.handler.set_user_instance("test_user")
        self.handler.set_auth_cookie_exist_instance(False)

        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.content = b""

        # Send response with headers
        self.handler.send_response_with_headers(mock_response)

        # Verify session is renewed (same session ID should be reused)
        self.assertIn(session_id1, session.sessions)
        self.assertEqual(len(session.sessions), 1)
        self.assertEqual(session.sessions[session_id1], "test_user")

        # Now simulate a different browser instance logging in with the same user
        # This should create a new session while keeping the existing one
        session_id2 = session.create_new_session("test_user")

        # Verify both sessions exist for the same user
        self.assertEqual(len(session.sessions), 2)
        self.assertIn(session_id1, session.sessions)
        self.assertIn(session_id2, session.sessions)
        self.assertEqual(session.sessions[session_id1], "test_user")
        self.assertEqual(session.sessions[session_id2], "test_user")

    def test_oauth_flow(self):
        """Test OAuth authentication flow"""
        # Mock thread-local OAuth session data
        with patch('oauth_handler.oauth_connector.get_oauth_session_data') as mock_get_session:
            mock_get_session.return_value = {
                'state': 'test_state',
                'created_at': time.time(),
                'redirect_uri': '/callback',
                'user_session_id': None
            }
            # Mock OAuth client responses
            with patch('oauth_handler.handler.check_state', return_value=True), \
                    patch('oauth_handler.oauth_connector.check_state', return_value=True):  # Need to patch both locations
                with patch('oauth_handler.oauth_connector.OAuthHTTPClient') as mock_client:
                    # Setup mock client
                    mock_client_instance = MagicMock()
                mock_client.return_value = mock_client_instance

                # Test successful OAuth flow
                mock_client_instance.get_token.return_value = "test_token"
                mock_client_instance.get_user.return_value = ("test_user", ["role1"])

                # Simulate OAuth callback with the correct redirect URI path
                self.handler.path = "/callback?state=test_state&code=test_code"  # Match the redirect_uri_path
                self.handler.headers = {}

                # Mock HTTP response methods
                self.handler.send_response = MagicMock()
                self.handler.send_header = MagicMock()
                self.handler.end_headers = MagicMock()

                # Mock graylog_handle to prevent actual Graylog calls
                with patch('oauth_handler.handler.graylog_handle') as mock_graylog:  # Patch the correct path
                    # Mock requests to prevent actual HTTP calls
                    with patch('requests.get') as mock_get, \
                            patch('requests.post') as mock_post, \
                            patch('requests.put') as mock_put:
                        # Setup mock responses
                        mock_token_response = MagicMock()
                        mock_token_response.status_code = 200
                        mock_token_response.text = '{"access_token": "test_token"}'
                        mock_token_response.json = lambda: {"access_token": "test_token"}
                        mock_token_response.content = b'{"access_token": "test_token"}'

                        mock_user_response = MagicMock()
                        mock_user_response.status_code = 200
                        mock_user_response.text = '{"preferred_username": "test_user", "realm_access": {"roles": ["role1"]}}'
                        mock_user_response.json = lambda: {
                            "preferred_username": "test_user", "realm_access": {"roles": ["role1"]}}
                        mock_user_response.content = b'{"preferred_username": "test_user", "realm_access": {"roles": ["role1"]}}'

                        # Mock Graylog response
                        mock_graylog_response = MagicMock()
                        mock_graylog_response.status_code = 200
                        mock_graylog_response.content = b'{"id": "test_user_id"}'
                        mock_graylog_response.json = lambda: {"id": "test_user_id"}

                        # Mock the requests to handle the Graylog API calls
                        def mock_request(*args, **kwargs):
                            url = args[0] if args else kwargs.get('url', '')
                            if 'api/users' in url:
                                return mock_graylog_response
                            return mock_user_response

                        mock_post.return_value = mock_token_response
                        mock_get.side_effect = mock_request
                        mock_put.return_value = mock_graylog_response

                        # Mock WebApplicationClient
                        with patch('oauthlib.oauth2.WebApplicationClient') as mock_web_client:
                            mock_web_client_instance = MagicMock()
                            mock_web_client.return_value = mock_web_client_instance
                            mock_web_client_instance.parse_request_body_response.return_value = None
                            mock_web_client_instance.token = {"access_token": "test_token"}

                            result = self.handler.auth_and_graylog_handle()
                            self.assertTrue(result)
                            self.assertEqual(self.handler.get_user(), "test_user")
                            # Verify graylog_handle was called with correct parameters
                            mock_graylog.assert_called_once_with(
                                self.graylog_config,
                                ["role1"],
                                "test_user"
                            )

    def test_error_handling(self):
        """Test error handling in various scenarios"""
        # Test invalid OAuth state
        self.handler.path = "/callback?state=invalid_state"
        self.handler.headers = {}

        with patch('oauth_handler.oauth_connector.check_state', return_value=False):
            self.assertFalse(self.handler.auth_and_graylog_handle())

        # Test OAuth token error
        with patch('oauth_handler.oauth_connector.OAuthHTTPClient') as mock_client:
            mock_client_instance = MagicMock()
            mock_client.return_value = mock_client_instance
            mock_client_instance.get_token.side_effect = Exception("Token error")

            self.handler.path = "/callback?state=test_state&code=test_code"
            self.handler.headers = {}

            with patch('oauth_handler.oauth_connector.check_state', return_value=True):
                self.assertFalse(self.handler.auth_and_graylog_handle())

    def test_options_request_with_root_path(self):
        """Test that OPTIONS requests to root path are handled properly"""
        # Use the existing handler from setUp
        self.handler.path = '/'

        # Mock common_params
        self.handler.common_params = MagicMock()
        self.handler.common_params.domain = '*'

        # Mock the send_response and send_header methods
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()

        # Call the OPTIONS method
        self.handler.do_OPTIONS()

        # Verify that CORS headers were sent
        self.handler.send_response.assert_called_with(200)
        self.handler.send_header.assert_any_call('Access-Control-Allow-Origin', '*')
        self.handler.end_headers.assert_called_once()

    def test_api_request_expired_session_returns_401(self):
        """Test that API requests with expired sessions return 401 instead of 302 redirect"""
        # Set up the handler with an API path
        self.handler.path = '/api/streams'
        self.handler.headers = {}

        # Mock the response methods
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()
        self.handler.wfile = MagicMock()

        # Mock the OAuth client to simulate expired session scenario
        with patch('oauth_handler.oauth_connector.OAuthHTTPClient') as mock_client:
            mock_client_instance = MagicMock()
            mock_client.return_value = mock_client_instance
            mock_client_instance.login.return_value = "https://oauth-provider.com/login"

            # Call the method that would normally redirect to OAuth
            result = self.handler._redirect_to_oauth_provider(mock_client_instance)

            # Verify that 401 was returned instead of 302
            self.assertFalse(result)
            self.handler.send_response.assert_called_with(401)
            self.handler.send_header.assert_any_call('Cache-Control', 'no-cache')
            self.handler.send_header.assert_any_call('Content-Type', 'application/json')
            self.handler.end_headers.assert_called_once()

            # Verify that JSON response body was sent
            self.handler.wfile.write.assert_called_once_with(b'{"message": "session expired"}')

            # Verify that no redirect was sent
            location_calls = [call for call in self.handler.send_header.call_args_list if call[0][0] == 'Location']
            self.assertEqual(len(location_calls), 0, "Location header should not be sent for API requests")

    def test_non_api_request_expired_session_returns_302(self):
        """Test that non-API requests with expired sessions still return 302 redirect"""
        # Set up the handler with a non-API path
        self.handler.path = '/dashboard'
        self.handler.headers = {}

        # Mock the response methods
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()

        # Mock the OAuth client
        with patch('oauth_handler.oauth_connector.OAuthHTTPClient') as mock_client:
            mock_client_instance = MagicMock()
            mock_client.return_value = mock_client_instance
            mock_client_instance.login.return_value = "https://oauth-provider.com/login"

            # Call the method that would normally redirect to OAuth
            result = self.handler._redirect_to_oauth_provider(mock_client_instance)

            # Verify that 302 redirect was returned
            self.assertFalse(result)
            self.handler.send_response.assert_called_with(302)
            self.handler.send_header.assert_any_call('Location', 'https://oauth-provider.com/login')
            self.handler.end_headers.assert_called_once()

    def test_api_request_expired_session_full_flow(self):
        """Test that API requests with expired sessions go through the full flow and return 401"""
        # Set up the handler with an API path and expired session
        self.handler.path = '/api/streams'
        self.handler.headers = {}

        # Mock the response methods
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()
        self.handler.wfile = MagicMock()

        # Mock cookie authentication to return False (expired session)
        with patch.object(self.handler, 'cookie_handle', return_value=False):
            # Mock the OAuth client
            with patch('oauth_handler.oauth_connector.OAuthHTTPClient') as mock_client:
                mock_client_instance = MagicMock()
                mock_client.return_value = mock_client_instance
                mock_client_instance.login.return_value = "https://oauth-provider.com/login"

                # Call the main authentication method
                result = self.handler.auth_and_graylog_handle()

                # Verify that 401 was returned instead of 302
                self.assertFalse(result)
                self.handler.send_response.assert_called_with(401)
                self.handler.send_header.assert_any_call('Cache-Control', 'no-cache')
                self.handler.send_header.assert_any_call('Content-Type', 'application/json')
                self.handler.end_headers.assert_called_once()

                # Verify that JSON response body was sent
                self.handler.wfile.write.assert_called_once_with(b'{"message": "session expired"}')

                # Verify that no redirect was sent
                location_calls = [call for call in self.handler.send_header.call_args_list if call[0][0] == 'Location']
                self.assertEqual(len(location_calls), 0, "Location header should not be sent for API requests")

    def test_technical_user_basic_auth_success(self):
        """Test successful Basic Auth authentication for technical users"""
        # Set up technical users in OAuth config
        self.oauth_config.technical_users_basic_auth_str = "monitoring:monitoring123,backup:backup456"
        self.oauth_config.technical_users_roles_str = "monitoring:Reader;backup:Admin"

        # Create Basic Auth header
        import base64
        credentials = base64.b64encode(b'monitoring:monitoring123').decode('utf-8')
        self.handler.headers = {
            'Authorization': f'Basic {credentials}'
        }

        # Mock graylog_handle
        with patch('basic_auth_handler.handler.graylog_handle') as mock_graylog_handle:
            result = self.handler.auth_and_graylog_handle()

            # Verify authentication succeeded
            self.assertTrue(result)
            self.assertEqual(self.handler.get_user(), 'monitoring')

            # Verify Graylog user/role management was called
            mock_graylog_handle.assert_called_once_with(
                self.graylog_config, ['Reader'], 'monitoring'
            )

    def test_technical_user_basic_auth_failure(self):
        """Test failed Basic Auth authentication for technical users"""
        # Set up technical users in OAuth config
        self.oauth_config.technical_users_basic_auth_str = "monitoring:monitoring123"

        # Create Basic Auth header with wrong password
        import base64
        credentials = base64.b64encode(b'monitoring:wrongpassword').decode('utf-8')
        self.handler.headers = {
            'Authorization': f'Basic {credentials}'
        }

        # Mock the response methods
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()

        # Mock OAuth client
        with patch('oauth_handler.oauth_connector.OAuthHTTPClient') as mock_client:
            mock_client_instance = MagicMock()
            mock_client.return_value = mock_client_instance
            mock_client_instance.login.return_value = "https://oauth-provider.com/login"

            result = self.handler.auth_and_graylog_handle()

            # Verify authentication failed and OAuth flow was initiated
            self.assertFalse(result)

    def test_technical_user_static_token_success(self):
        """Test successful static token authentication for technical users"""
        # Set up technical users in OAuth config
        self.oauth_config.technical_users_static_tokens_str = "api-client:abc123def456,service-account:xyz789uvw012"
        self.oauth_config.technical_users_roles_str = "api-client:Admin;service-account:Reader"

        # Create Bearer token header
        self.handler.headers = {
            'Authorization': 'Bearer abc123def456'
        }

        # Mock graylog_handle
        with patch('basic_auth_handler.handler.graylog_handle') as mock_graylog_handle:
            result = self.handler.auth_and_graylog_handle()

            # Verify authentication succeeded
            self.assertTrue(result)
            self.assertEqual(self.handler.get_user(), 'api-client')

            # Verify Graylog user/role management was called
            mock_graylog_handle.assert_called_once_with(
                self.graylog_config, ['Admin'], 'api-client'
            )

    def test_technical_user_static_token_failure(self):
        """Test failed static token authentication for technical users"""
        # Set up technical users in OAuth config
        self.oauth_config.technical_users_static_tokens_str = "api-client:abc123def456"

        # Create Bearer token header with wrong token
        self.handler.headers = {
            'Authorization': 'Bearer wrongtoken'
        }

        # Mock the response methods
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()

        # Mock OAuth client
        with patch('oauth_handler.oauth_connector.OAuthHTTPClient') as mock_client:
            mock_client_instance = MagicMock()
            mock_client.return_value = mock_client_instance
            mock_client_instance.login.return_value = "https://oauth-provider.com/login"

            result = self.handler.auth_and_graylog_handle()

            # Verify authentication failed and OAuth flow was initiated
            self.assertFalse(result)

    def test_technical_user_default_roles(self):
        """Test that technical users get default roles when not specified"""
        # Set up technical users in OAuth config without roles
        self.oauth_config.technical_users_basic_auth_str = "monitoring:monitoring123"
        self.oauth_config.technical_users_roles_str = ""

        # Create Basic Auth header
        import base64
        credentials = base64.b64encode(b'monitoring:monitoring123').decode('utf-8')
        self.handler.headers = {
            'Authorization': f'Basic {credentials}'
        }

        # Mock graylog_handle
        with patch('basic_auth_handler.handler.graylog_handle') as mock_graylog_handle:
            result = self.handler.auth_and_graylog_handle()

            # Verify authentication succeeded
            self.assertTrue(result)
            self.assertEqual(self.handler.get_user(), 'monitoring')

            # Verify Graylog user/role management was called with default roles
            mock_graylog_handle.assert_called_once_with(
                self.graylog_config, common_vars.DEFAULT_ROLES, 'monitoring'
            )

    def test_legacy_basic_auth_still_works(self):
        """Test that legacy Basic Auth format still works for admin user"""
        # Create legacy Basic Auth header (without 'Basic ' prefix)
        import base64
        credentials = base64.b64encode(b'admin:admin123').decode('utf-8')
        self.handler.headers = {
            'Authorization': credentials
        }

        result = self.handler.auth_and_graylog_handle()

        # Verify authentication succeeded for admin user
        self.assertTrue(result)
        self.assertEqual(self.handler.get_user(), 'admin')

    def test_admin_standard_basic_auth(self):
        """Test that standard Basic Auth format works for admin user"""
        # Create standard Basic Auth header (with 'Basic ' prefix)
        import base64
        credentials = base64.b64encode(b'admin:admin123').decode('utf-8')
        self.handler.headers = {
            'Authorization': f'Basic {credentials}'
        }

        result = self.handler.auth_and_graylog_handle()

        # Verify authentication succeeded for admin user
        self.assertTrue(result)
        self.assertEqual(self.handler.get_user(), 'admin')

    def test_admin_auth_headers_passthrough(self):
        """Test that admin user's Authorization header is passed through to Graylog"""
        # Create standard Basic Auth header for admin
        import base64
        credentials = base64.b64encode(b'admin:admin123').decode('utf-8')
        self.handler.headers = {
            'Authorization': f'Basic {credentials}'
        }

        # Set user to admin (simulating successful authentication)
        self.handler.set_user_instance('admin')
        self.handler.path = '/api/users'

        # Parse headers
        parsed_headers = self.handler.parse_headers()

        # Verify Authorization header is preserved for admin
        self.assertIn('Authorization', parsed_headers)
        self.assertEqual(parsed_headers['Authorization'], f'Basic {credentials}')
        # Verify X-Forwarded-User is NOT added for admin
        self.assertNotIn('X-Forwarded-User', parsed_headers)

    def test_regular_user_auth_headers_removed(self):
        """Test that regular user's Authorization header is removed"""
        # Create standard Basic Auth header
        import base64
        credentials = base64.b64encode(b'regularuser:password').decode('utf-8')
        self.handler.headers = {
            'Authorization': f'Basic {credentials}'
        }

        # Set user to regular user (simulating successful authentication)
        self.handler.set_user_instance('regularuser')
        self.handler.path = '/api/users'

        # Parse headers
        parsed_headers = self.handler.parse_headers()

        # Verify Authorization header is removed for regular user
        self.assertNotIn('Authorization', parsed_headers)
        # Verify X-Forwarded-User is added for regular user
        self.assertIn('X-Forwarded-User', parsed_headers)
        self.assertEqual(parsed_headers['X-Forwarded-User'], 'regularuser')

    def test_admin_user_oauth_flow_skips_graylog_management(self):
        """Test that admin user going through OAuth doesn't trigger Graylog user management"""
        # Mock thread-local OAuth session data
        with patch('oauth_handler.oauth_connector.get_oauth_session_data') as mock_get_session:
            mock_get_session.return_value = {
                'state': 'test_state',
                'created_at': time.time(),
                'redirect_uri': '/callback',
                'user_session_id': None
            }
            # Mock OAuth client responses
            with patch('oauth_handler.handler.check_state', return_value=True), \
                    patch('oauth_handler.oauth_connector.check_state', return_value=True):
                with patch('oauth_handler.oauth_connector.OAuthHTTPClient') as mock_client:
                    # Setup mock client
                    mock_client_instance = MagicMock()
                    mock_client.return_value = mock_client_instance

                    # Admin user authenticates via OAuth
                    mock_client_instance.get_token.return_value = "test_token"
                    mock_client_instance.get_user.return_value = ("admin", ["role1"])

                    # Simulate OAuth callback with the correct redirect URI path
                    self.handler.path = "/callback?state=test_state&code=test_code"
                    self.handler.headers = {}

                    # Mock HTTP response methods
                    self.handler.send_response = MagicMock()
                    self.handler.send_header = MagicMock()
                    self.handler.end_headers = MagicMock()

                    # Mock graylog_handle to verify it's NOT called for admin user
                    with patch('oauth_handler.handler.graylog_handle') as mock_graylog:
                        # Mock requests to prevent actual HTTP calls
                        with patch('requests.get') as mock_get, \
                                patch('requests.post') as mock_post, \
                                patch('requests.put') as mock_put:
                            # Setup mock responses
                            mock_token_response = MagicMock()
                            mock_token_response.status_code = 200
                            mock_token_response.text = '{"access_token": "test_token"}'
                            mock_token_response.json = lambda: {"access_token": "test_token"}
                            mock_token_response.content = b'{"access_token": "test_token"}'

                            mock_user_response = MagicMock()
                            mock_user_response.status_code = 200
                            mock_user_response.text = '{"preferred_username": "admin", "realm_access": {"roles": ["role1"]}}'
                            mock_user_response.json = lambda: {
                                "preferred_username": "admin", "realm_access": {"roles": ["role1"]}}
                            mock_user_response.content = b'{"preferred_username": "admin", "realm_access": {"roles": ["role1"]}}'

                            mock_post.return_value = mock_token_response
                            mock_get.return_value = mock_user_response
                            mock_put.return_value = mock_user_response

                            # Mock WebApplicationClient
                            with patch('oauthlib.oauth2.WebApplicationClient') as mock_web_client:
                                mock_web_client_instance = MagicMock()
                                mock_web_client.return_value = mock_web_client_instance
                                mock_web_client_instance.parse_request_body_response.return_value = None
                                mock_web_client_instance.token = {"access_token": "test_token"}

                                result = self.handler.auth_and_graylog_handle()
                                self.assertTrue(result)
                                self.assertEqual(self.handler.get_user(), "admin")

                                # Verify graylog_handle was NOT called for admin user
                                mock_graylog.assert_not_called()

    def test_technical_users_parsing(self):
        """Test parsing of technical users configuration"""
        from basic_auth_handler import BasicAuthConfig

        # Test Basic Auth parsing
        basic_auth_str = "user1:pass1,user2:pass2"
        config = BasicAuthConfig.from_strings(basic_auth_str, "", "")
        self.assertEqual(config.basic_auth_users, {'user1': 'pass1', 'user2': 'pass2'})

        # Test static tokens parsing
        tokens_str = "user1:token1,user2:token2"
        config = BasicAuthConfig.from_strings("", tokens_str, "")
        self.assertEqual(config.static_token_users, {'user1': 'token1', 'user2': 'token2'})

        # Test roles parsing
        roles_str = "user1:role1,role2;user2:role3"
        config = BasicAuthConfig.from_strings("", "", roles_str)
        self.assertEqual(config.user_roles, {'user1': ['role1', 'role2'], 'user2': ['role3']})

        # Test empty strings
        config = BasicAuthConfig.from_strings("", "", "")
        self.assertEqual(config.basic_auth_users, {})
        self.assertEqual(config.static_token_users, {})
        self.assertEqual(config.user_roles, {})

    def test_api_request_expired_session_json_response(self):
        """Test that API requests with expired sessions return the correct JSON response"""
        # Set up the handler with an API path
        self.handler.path = '/api/streams'
        self.handler.headers = {}

        # Mock the response methods
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()
        self.handler.wfile = MagicMock()

        # Mock the OAuth client to simulate expired session scenario
        with patch('oauth_handler.oauth_connector.OAuthHTTPClient') as mock_client:
            mock_client_instance = MagicMock()
            mock_client.return_value = mock_client_instance
            mock_client_instance.login.return_value = "https://oauth-provider.com/login"

            # Call the method that would normally redirect to OAuth
            result = self.handler._redirect_to_oauth_provider(mock_client_instance)

            # Verify that 401 was returned
            self.assertFalse(result)
            self.handler.send_response.assert_called_with(401)

            # Verify all required headers were sent
            self.handler.send_header.assert_any_call('Cache-Control', 'no-cache')
            self.handler.send_header.assert_any_call('Content-Type', 'application/json')
            self.handler.end_headers.assert_called_once()

            # Verify the exact JSON response body
            expected_json = '{"message": "session expired"}'
            self.handler.wfile.write.assert_called_once_with(expected_json.encode('utf-8'))

            # Verify that no redirect was sent
            location_calls = [call for call in self.handler.send_header.call_args_list if call[0][0] == 'Location']
            self.assertEqual(len(location_calls), 0, "Location header should not be sent for API requests")


if __name__ == '__main__':
    unittest.main()
