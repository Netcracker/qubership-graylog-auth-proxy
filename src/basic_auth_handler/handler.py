import base64
from typing import Dict, List

import common.log as log
import common.vars as common_vars
from common.graylog import graylog_handle

logger = log.get_logger(__name__)


class BasicAuthConfig:
    """Configuration for technical users authentication"""

    def __init__(self, basic_auth_users: Dict[str, str] = None,
                 static_token_users: Dict[str, str] = None,
                 user_roles: Dict[str, List[str]] = None):
        self.basic_auth_users = basic_auth_users or {}
        self.static_token_users = static_token_users or {}
        self.user_roles = user_roles or {}

    @classmethod
    def from_strings(cls, basic_auth_str: str = "", static_tokens_str: str = "", roles_str: str = ""):
        """Create BasicAuthConfig from configuration strings"""
        basic_auth_users = cls._parse_basic_auth_users(basic_auth_str)
        static_token_users = cls._parse_static_token_users(static_tokens_str)
        user_roles = cls._parse_user_roles(roles_str)

        return cls(basic_auth_users, static_token_users, user_roles)

    @staticmethod
    def _parse_basic_auth_users(basic_auth_str: str) -> Dict[str, str]:
        """Parse technical users Basic Auth configuration"""
        if not basic_auth_str:
            return {}

        users = {}
        for user_entry in basic_auth_str.split(','):
            user_entry = user_entry.strip()
            if ':' in user_entry:
                username, password = user_entry.split(':', 1)
                users[username.strip()] = password.strip()
        return users

    @staticmethod
    def _parse_static_token_users(tokens_str: str) -> Dict[str, str]:
        """Parse technical users static tokens configuration"""
        if not tokens_str:
            return {}

        users = {}
        for user_entry in tokens_str.split(','):
            user_entry = user_entry.strip()
            if ':' in user_entry:
                username, token = user_entry.split(':', 1)
                users[username.strip()] = token.strip()
        return users

    @staticmethod
    def _parse_user_roles(roles_str: str) -> Dict[str, List[str]]:
        """Parse technical users roles configuration"""
        if not roles_str:
            return {}

        users = {}
        for user_entry in roles_str.split(';'):
            user_entry = user_entry.strip()
            if ':' in user_entry:
                username, roles = user_entry.split(':', 1)
                user_roles = [role.strip() for role in roles.split(',')]
                users[username.strip()] = user_roles
        return users


class BasicAuthHandler:
    """Handler for technical users authentication (Basic Auth and Static Tokens)"""

    def __init__(self, config: BasicAuthConfig, graylog_config, common_config):
        self.config = config
        self.graylog_config = graylog_config
        self.common_config = common_config

    def handle_authentication(self, auth_header: str, set_user_callback, get_user_callback) -> bool:
        """
        Handle technical users authentication
        Technical users bypass session management and don't use cookies

        Args:
            auth_header: The Authorization header value
            set_user_callback: Callback to set the authenticated user
            get_user_callback: Callback to get the current user

        Returns:
            True if authentication succeeded, False otherwise
        """
        if not auth_header:
            return False

        # Check for Basic Auth first
        if auth_header.startswith('Basic '):
            return self._handle_basic_auth(auth_header, set_user_callback)

        # Check for Bearer token (static token)
        elif auth_header.startswith('Bearer '):
            return self._handle_static_token(auth_header, set_user_callback)

        # Handle legacy Basic Auth format (Authorization: <base64>)
        else:
            return self._handle_legacy_basic_auth(auth_header, set_user_callback)

    def _handle_basic_auth(self, auth_header: str, set_user_callback) -> bool:
        """Handle Basic Auth for technical users"""
        try:
            # Extract credentials from Basic Auth header
            auth_decoded = base64.b64decode(auth_header[6:])  # Remove 'Basic ' prefix
            auth_decoded = auth_decoded.decode("utf-8")
            user, password = auth_decoded.split(':', 1)

            # Check if user is in technical users list
            if user in self.config.basic_auth_users and self.config.basic_auth_users[user] == password:
                logger.debug(f'Technical user authenticated via Basic Auth: {user}')
                set_user_callback(user)

                # Get roles for this technical user
                roles = self._get_technical_user_roles(user)

                # Handle Graylog user/role management (don't fail auth if Graylog fails)
                try:
                    graylog_handle(self.graylog_config, roles, user)
                except Exception as e:
                    logger.warning(f"Graylog user/role management failed for user {user}: {e}")
                    # Don't fail authentication if Graylog is unavailable

                return True
            else:
                logger.debug(f'Basic Auth failed for technical user: {user}')
                return False

        except Exception as e:
            logger.debug(f"Failed to process Basic Auth: {e}")
            return False

    def _handle_static_token(self, auth_header: str, set_user_callback) -> bool:
        """Handle static token authentication for technical users"""
        try:
            # Extract token from Bearer header
            token = auth_header[7:]  # Remove 'Bearer ' prefix

            # Check if token matches any technical user
            for username, user_token in self.config.static_token_users.items():
                if user_token == token:
                    logger.debug(f'Technical user authenticated via static token: {username}')
                    set_user_callback(username)

                    # Get roles for this technical user
                    roles = self._get_technical_user_roles(username)

                    # Handle Graylog user/role management (don't fail auth if Graylog fails)
                    try:
                        graylog_handle(self.graylog_config, roles, username)
                    except Exception as e:
                        logger.warning(f"Graylog user/role management failed for user {username}: {e}")
                        # Don't fail authentication if Graylog is unavailable

                    return True

            logger.debug('Static token authentication failed')
            return False

        except Exception as e:
            logger.debug(f"Failed to process static token: {e}")
            return False

    def _handle_legacy_basic_auth(self, auth_header: str, set_user_callback) -> bool:
        """Handle legacy Basic Auth format for admin user"""
        try:
            auth_decoded = base64.b64decode(auth_header)
            auth_decoded = auth_decoded.decode("utf-8")
            user, passwd = auth_decoded.split(':', 1)

            # Skip OAuth2 flow if user try to login under local admin
            if user == common_vars.DEFAULT_ADMIN_USER:
                set_user_callback(user)
                logger.debug('Log in as default admin user: skip OAuth authentication')
                return True

        except Exception as e:
            logger.debug(f"Failed to decode Authorization header: {e}")

        return False

    def _get_technical_user_roles(self, username: str) -> List[str]:
        """Get roles for a technical user"""
        if username in self.config.user_roles:
            return self.config.user_roles[username]
        else:
            # Return default roles if none specified
            return common_vars.DEFAULT_ROLES
