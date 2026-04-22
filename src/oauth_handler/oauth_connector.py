import logging
import secrets
import time
import threading
from typing import Optional, Tuple

import jsonpath_ng
import requests
from oauthlib.oauth2 import WebApplicationClient

from common import log
from config.oauth import OAuthConfig

logger = log.get_logger(__name__)
logging.getLogger("urllib3").setLevel(logging.ERROR)


# Global OAuth session cache with thread-safe access
_oauth_session_cache = {}
_oauth_session_lock = threading.Lock()


def get_oauth_session_data():
    """Get thread-local OAuth session data with fallback to global cache"""
    thread_id = threading.current_thread().ident

    # First try to get from thread-local storage
    if not hasattr(threading.current_thread(), '_oauth_session_data'):
        # If not in thread-local, check global cache
        with _oauth_session_lock:
            if thread_id in _oauth_session_cache:
                # Move from global cache to thread-local
                threading.current_thread()._oauth_session_data = _oauth_session_cache[thread_id]
                del _oauth_session_cache[thread_id]
            else:
                # Create new thread-local data
                threading.current_thread()._oauth_session_data = {
                    'state': None,
                    'created_at': None,
                    'redirect_uri': None,
                    'user_session_id': None,
                    'original_request_url': None
                }

    return threading.current_thread()._oauth_session_data


def store_oauth_session_data(session_data):
    """Store OAuth session data in global cache for cross-thread access"""
    thread_id = threading.current_thread().ident
    with _oauth_session_lock:
        _oauth_session_cache[thread_id] = session_data.copy()


def clear_oauth_session():
    """Clear OAuth session data from both thread-local and global cache"""
    thread_id = threading.current_thread().ident

    # Clear thread-local data
    if hasattr(threading.current_thread(), '_oauth_session_data'):
        delattr(threading.current_thread(), '_oauth_session_data')

    # Clear from global cache
    with _oauth_session_lock:
        if thread_id in _oauth_session_cache:
            del _oauth_session_cache[thread_id]


def cleanup_expired_sessions():
    """Clean up expired OAuth sessions from global cache"""
    current_time = time.time()
    expired_threads = []

    with _oauth_session_lock:
        for thread_id, session_data in _oauth_session_cache.items():
            created_at = session_data.get('created_at')
            if created_at and (current_time - created_at) > 300:  # 5 minutes
                expired_threads.append(thread_id)

        for thread_id in expired_threads:
            del _oauth_session_cache[thread_id]


def check_state(state: str) -> bool:
    """Validate OAuth state parameter with expiration check"""
    if not state:
        return False

    # Clean up expired sessions first
    cleanup_expired_sessions()

    # Check thread-local data
    oauth_session_data = get_oauth_session_data()
    if oauth_session_data.get('state'):
        # Check if state has expired (5 minutes)
        created_at = oauth_session_data.get('created_at')
        if created_at and (time.time() - created_at) > 300:  # 5 minutes
            logger.warning("OAuth state has expired")
            clear_oauth_session()
            return False

        if oauth_session_data['state'] == state:
            return True

    # Check global cache for other threads
    with _oauth_session_lock:
        for thread_id, session_data in _oauth_session_cache.items():
            if session_data.get('state') == state:
                # Check if state has expired
                created_at = session_data.get('created_at')
                if created_at and (time.time() - created_at) > 300:  # 5 minutes
                    logger.warning("OAuth state has expired")
                    del _oauth_session_cache[thread_id]
                    return False

                # Move to current thread and return True
                threading.current_thread()._oauth_session_data = session_data.copy()
                del _oauth_session_cache[thread_id]
                return True

    return False


def create_oauth_state(user_session_id: Optional[str] = None) -> str:
    """Create a new OAuth state with optional user session linking"""
    oauth_session_data = get_oauth_session_data()
    state = secrets.token_urlsafe(32)  # Increased entropy
    oauth_session_data['state'] = state
    oauth_session_data['created_at'] = time.time()
    oauth_session_data['user_session_id'] = user_session_id

    # Store in global cache for cross-thread access
    store_oauth_session_data(oauth_session_data)

    return state


class OAuthHTTPClient:
    def __init__(self, params: OAuthConfig):
        self.params = params

    def login(self, user_session_id: Optional[str] = None, redirect_uri: Optional[str] = None) -> Optional[str]:
        """Initiate OAuth login with improved state management"""
        try:
            client = WebApplicationClient(self.params.client_id)

            # Create new state
            state = create_oauth_state(user_session_id)

            # Use provided redirect URI or default
            oauth_session_data = get_oauth_session_data()
            final_redirect_uri = redirect_uri or self.params.redirect_uri
            oauth_session_data['redirect_uri'] = final_redirect_uri

            # Update global cache with redirect URI
            store_oauth_session_data(oauth_session_data)

            url_to_redirect = client.prepare_request_uri(
                self.params.authorization_url,
                redirect_uri=final_redirect_uri,
                scope=[self.params.scopes],
                state=state,
                allow_signup='false'
            )

            logger.debug(f"Generated OAuth login URL with state: {state[:8]}...")
            return url_to_redirect

        except Exception as e:
            logger.error(f"Failed to generate OAuth login URL: {e}")
            clear_oauth_session()
            return None

    def get_token(self, code: str) -> Optional[str]:
        """Exchange authorization code for access token with improved error handling"""
        try:
            client = WebApplicationClient(self.params.client_id)
            oauth_session_data = get_oauth_session_data()

            # Prepare body for request
            data = client.prepare_request_body(
                code=code,
                redirect_uri=oauth_session_data.get('redirect_uri', self.params.redirect_uri),
                include_client_id=True,
                client_secret=self.params.client_secret
            )

            token_header = {'Content-Type': 'application/x-www-form-urlencoded'}
            response = requests.post(
                self.params.token_url,
                headers=token_header,
                data=data,
                verify=self.params.verify,
                cert=self.params.cert,
                timeout=self.params.timeout
            )

            if not response.ok:
                logger.error(f'Token request failed with status {response.status_code}: {response.text}')
                return None

            client.parse_request_body_response(response.text)

            token = client.token.get('access_token', None)
            if not token:
                logger.error("No access token in OAuth response")
                return None

            logger.debug("Successfully obtained access token")
            return token

        except Exception as e:
            logger.error(f"Error during token exchange: {e}")
            return None

    def get_user(self, token: str) -> Tuple[str, list[str]]:
        """Get user information from OAuth provider with improved error handling"""
        if not token:
            logger.error("Access token is empty")
            return "", []

        try:
            header = {'Authorization': f'Bearer {token}'}

            response = requests.get(
                self.params.userinfo_url,
                headers=header,
                verify=self.params.verify,
                cert=self.params.cert,
                timeout=self.params.timeout
            )

            if not response.ok:
                logger.error(f'Userinfo request failed with status {response.status_code}: {response.text}')
                return "", []

            json_dict = response.json()

            # Extract username
            user_expr = jsonpath_ng.parse(self.params.user_jsonpath)
            user_list = user_expr.find(json_dict)
            if not user_list:
                logger.error(f"No user found using pattern: {self.params.user_jsonpath}")
                return "", []

            user = user_list[0].value
            if not user:
                logger.error("User value is empty")
                return "", []

            # Extract roles
            roles = []
            if self.params.roles_jsonpath:
                roles_expr = jsonpath_ng.parse(self.params.roles_jsonpath)
                roles = [match.value for match in roles_expr.find(json_dict)]

            logger.debug(f"Successfully obtained user info: {user} with {len(roles)} roles")
            return user, roles

        except Exception as e:
            logger.error(f"Error during userinfo request: {e}")
            return "", []

    def refresh_token_if_needed(self, refresh_token: str) -> Optional[str]:
        """Refresh access token using refresh token (if supported by OAuth provider)"""
        try:
            client = WebApplicationClient(self.params.client_id)

            data = client.prepare_request_body(
                grant_type='refresh_token',
                refresh_token=refresh_token,
                include_client_id=True,
                client_secret=self.params.client_secret
            )

            token_header = {'Content-Type': 'application/x-www-form-urlencoded'}
            response = requests.post(
                self.params.token_url,
                headers=token_header,
                data=data,
                verify=self.params.verify,
                cert=self.params.cert,
                timeout=self.params.timeout
            )

            if not response.ok:
                logger.error(f'Token refresh failed with status {response.status_code}')
                return None

            client.parse_request_body_response(response.text)
            return client.token.get('access_token', None)

        except Exception as e:
            logger.error(f"Error during token refresh: {e}")
            return None
