import unittest
from unittest.mock import MagicMock, patch

import common.vars as common_vars
from basic_auth_handler import BasicAuthHandler, BasicAuthConfig


class TestBasicAuthConfig(unittest.TestCase):
    """Test the BasicAuthConfig class"""

    def test_empty_config(self):
        """Test creating config with empty strings"""
        config = BasicAuthConfig.from_strings("", "", "")
        self.assertEqual(config.basic_auth_users, {})
        self.assertEqual(config.static_token_users, {})
        self.assertEqual(config.user_roles, {})

    def test_basic_auth_parsing(self):
        """Test parsing Basic Auth users"""
        basic_auth_str = "user1:pass1,user2:pass2"
        config = BasicAuthConfig.from_strings(basic_auth_str, "", "")
        self.assertEqual(config.basic_auth_users, {'user1': 'pass1', 'user2': 'pass2'})

    def test_static_tokens_parsing(self):
        """Test parsing static token users"""
        tokens_str = "user1:token1,user2:token2"
        config = BasicAuthConfig.from_strings("", tokens_str, "")
        self.assertEqual(config.static_token_users, {'user1': 'token1', 'user2': 'token2'})

    def test_roles_parsing(self):
        """Test parsing user roles"""
        roles_str = "user1:role1,role2;user2:role3"
        config = BasicAuthConfig.from_strings("", "", roles_str)
        self.assertEqual(config.user_roles, {'user1': ['role1', 'role2'], 'user2': ['role3']})

    def test_complex_config(self):
        """Test creating config with all parameters"""
        basic_auth_str = "monitoring:pass123"
        tokens_str = "api-client:token456"
        roles_str = "monitoring:Reader;api-client:Admin"

        config = BasicAuthConfig.from_strings(basic_auth_str, tokens_str, roles_str)

        self.assertEqual(config.basic_auth_users, {'monitoring': 'pass123'})
        self.assertEqual(config.static_token_users, {'api-client': 'token456'})
        self.assertEqual(config.user_roles, {'monitoring': ['Reader'], 'api-client': ['Admin']})

    def test_malformed_strings(self):
        """Test handling of malformed configuration strings"""
        # Missing colons
        config = BasicAuthConfig.from_strings("user1,user2", "token1,token2", "role1,role2")
        self.assertEqual(config.basic_auth_users, {})
        self.assertEqual(config.static_token_users, {})
        self.assertEqual(config.user_roles, {})

        # Empty entries
        config = BasicAuthConfig.from_strings("user1:,user2:pass", "token1:,token2:token", "role1:,role2:role")
        self.assertEqual(config.basic_auth_users, {'user1': '', 'user2': 'pass'})
        self.assertEqual(config.static_token_users, {'token1': '', 'token2': 'token'})
        self.assertEqual(config.user_roles, {'role1': ['', 'role2:role']})


class TestBasicAuthHandler(unittest.TestCase):
    """Test the BasicAuthHandler class"""

    def setUp(self):
        """Set up test fixtures"""
        # Create mock configurations
        self.mock_graylog_config = MagicMock()
        self.mock_common_config = MagicMock()

        # Create technical users config
        self.technical_users_config = BasicAuthConfig(
            basic_auth_users={'monitoring': 'monitoring123', 'backup': 'backup456'},
            static_token_users={'api-client': 'abc123def456', 'service-account': 'xyz789uvw012'},
            user_roles={'monitoring': ['Reader'], 'api-client': ['Admin'], 'backup': ['Reader']}
        )

        # Create handler
        self.handler = BasicAuthHandler(
            self.technical_users_config,
            self.mock_graylog_config,
            self.mock_common_config
        )

    def test_handle_authentication_no_header(self):
        """Test authentication with no Authorization header"""
        set_user_callback = MagicMock()
        get_user_callback = MagicMock()

        result = self.handler.handle_authentication("", set_user_callback, get_user_callback)

        self.assertFalse(result)
        set_user_callback.assert_not_called()

    def test_handle_basic_auth_success(self):
        """Test successful Basic Auth authentication"""
        import base64
        credentials = base64.b64encode(b'monitoring:monitoring123').decode('utf-8')
        auth_header = f'Basic {credentials}'

        set_user_callback = MagicMock()
        get_user_callback = MagicMock()

        with patch('basic_auth_handler.handler.graylog_handle') as mock_graylog_handle:
            result = self.handler.handle_authentication(auth_header, set_user_callback, get_user_callback)

            self.assertTrue(result)
            set_user_callback.assert_called_once_with('monitoring')
            mock_graylog_handle.assert_called_once_with(
                self.mock_graylog_config, ['Reader'], 'monitoring'
            )

    def test_handle_basic_auth_failure(self):
        """Test failed Basic Auth authentication"""
        import base64
        credentials = base64.b64encode(b'monitoring:wrongpassword').decode('utf-8')
        auth_header = f'Basic {credentials}'

        set_user_callback = MagicMock()
        get_user_callback = MagicMock()

        result = self.handler.handle_authentication(auth_header, set_user_callback, get_user_callback)

        self.assertFalse(result)
        set_user_callback.assert_not_called()

    def test_handle_static_token_success(self):
        """Test successful static token authentication"""
        auth_header = 'Bearer abc123def456'

        set_user_callback = MagicMock()
        get_user_callback = MagicMock()

        with patch('basic_auth_handler.handler.graylog_handle') as mock_graylog_handle:
            result = self.handler.handle_authentication(auth_header, set_user_callback, get_user_callback)

            self.assertTrue(result)
            set_user_callback.assert_called_once_with('api-client')
            mock_graylog_handle.assert_called_once_with(
                self.mock_graylog_config, ['Admin'], 'api-client'
            )

    def test_handle_static_token_failure(self):
        """Test failed static token authentication"""
        auth_header = 'Bearer wrongtoken'

        set_user_callback = MagicMock()
        get_user_callback = MagicMock()

        result = self.handler.handle_authentication(auth_header, set_user_callback, get_user_callback)

        self.assertFalse(result)
        set_user_callback.assert_not_called()

    def test_handle_legacy_basic_auth_admin(self):
        """Test legacy Basic Auth for admin user"""
        import base64
        credentials = base64.b64encode(f'{common_vars.DEFAULT_ADMIN_USER}:admin123'.encode()).decode('utf-8')
        auth_header = credentials  # No 'Basic ' prefix

        set_user_callback = MagicMock()
        get_user_callback = MagicMock()

        result = self.handler.handle_authentication(auth_header, set_user_callback, get_user_callback)

        self.assertTrue(result)
        set_user_callback.assert_called_once_with(common_vars.DEFAULT_ADMIN_USER)

    def test_handle_legacy_basic_auth_non_admin(self):
        """Test legacy Basic Auth for non-admin user"""
        import base64
        credentials = base64.b64encode(b'regularuser:password').decode('utf-8')
        auth_header = credentials  # No 'Basic ' prefix

        set_user_callback = MagicMock()
        get_user_callback = MagicMock()

        result = self.handler.handle_authentication(auth_header, set_user_callback, get_user_callback)

        self.assertFalse(result)
        set_user_callback.assert_not_called()

    def test_default_roles(self):
        """Test that users get default roles when not specified"""
        # Create config without roles for a user
        config = BasicAuthConfig(
            basic_auth_users={'testuser': 'testpass'},
            static_token_users={},
            user_roles={}  # No roles specified
        )

        handler = BasicAuthHandler(config, self.mock_graylog_config, self.mock_common_config)

        import base64
        credentials = base64.b64encode(b'testuser:testpass').decode('utf-8')
        auth_header = f'Basic {credentials}'

        set_user_callback = MagicMock()
        get_user_callback = MagicMock()

        with patch('basic_auth_handler.handler.graylog_handle') as mock_graylog_handle:
            result = handler.handle_authentication(auth_header, set_user_callback, get_user_callback)

            self.assertTrue(result)
            set_user_callback.assert_called_once_with('testuser')
            mock_graylog_handle.assert_called_once_with(
                self.mock_graylog_config, common_vars.DEFAULT_ROLES, 'testuser'
            )

    def test_malformed_auth_header(self):
        """Test handling of malformed Authorization headers"""
        set_user_callback = MagicMock()
        get_user_callback = MagicMock()

        # Invalid base64
        result = self.handler.handle_authentication('Basic invalid-base64', set_user_callback, get_user_callback)
        self.assertFalse(result)

        # Missing colon in credentials
        import base64
        credentials = base64.b64encode(b'usernameonly').decode('utf-8')
        result = self.handler.handle_authentication(f'Basic {credentials}', set_user_callback, get_user_callback)
        self.assertFalse(result)

        # Empty Bearer token
        result = self.handler.handle_authentication('Bearer ', set_user_callback, get_user_callback)
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
