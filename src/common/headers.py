import datetime
import re
from datetime import timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

import common.log as log
import common.session as session
import common.vars as common_vars

logger = log.get_logger(__name__)


class HeaderHandler:
    """Common header handling functionality for both OAuth and LDAP handlers"""

    def __init__(self, handler: BaseHTTPRequestHandler, common_params, auth_params=None, graylog_params=None):
        self.handler = handler
        self.common_params = common_params
        self.auth_params = auth_params
        self.graylog_params = graylog_params
        self.user = None
        self.auth_cookie_exist = False

    def set_user(self, user: str):
        self.user = user

    def get_user(self) -> str:
        return self.user

    def set_auth_cookie_exist(self, auth_cookie_exist: bool):
        self.auth_cookie_exist = auth_cookie_exist

    def get_auth_cookie_exist(self) -> bool:
        return self.auth_cookie_exist

    def get_cookie(self, name):
        """Get cookie value by name from request headers"""
        cookies = self.handler.headers.get('Cookie')
        if cookies:
            auth_cookie = SimpleCookie(cookies).get(name)
            if auth_cookie:
                return auth_cookie.value
            else:
                return None
        else:
            return None

    def set_cookie(self, cookie, cookie_name, cookie_value, max_age=None, expires_hours=None):
        """Set cookie with proper attributes"""
        # Use config values if not provided
        if max_age is None:
            max_age = self.common_params.cookie_max_age
        if expires_hours is None:
            expires_hours = self.common_params.cookie_expires_hours

        cookie[cookie_name] = cookie_value
        cookie[cookie_name]['path'] = '/'
        cookie[cookie_name]['max-age'] = max_age

        expires = datetime.datetime.now(timezone.utc) + datetime.timedelta(hours=expires_hours)
        cookie[cookie_name]['expires'] = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
        return cookie

    def add_cors_headers(self):
        """Add CORS headers to the response"""
        cors_origin = self.get_cors_origin_header()
        self.handler.send_header('Access-Control-Allow-Origin', cors_origin)
        self.handler.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.handler.send_header(
            'Access-Control-Allow-Headers',
            'Content-Type, Authorization, X-Requested-With, X-Requested-By, X-Graylog-No-Session-Extension')
        self.handler.send_header('Access-Control-Allow-Credentials', 'true')

    def add_cors_headers_with_cache(self):
        """Add CORS headers with cache control for preflight requests"""
        self.add_cors_headers()

        # Cache preflight based on configuration
        self.handler.send_header('Access-Control-Max-Age', self.common_params.access_control_max_age)

    def get_cors_origin_header(self):
        """Get the appropriate CORS origin header based on configured domain"""
        # Get domain from config, default to '*' if not set
        return getattr(self.common_params, 'domain', '*')

    def send_resp_headers(self, resp, cookies=None):
        """Send response headers with CORS and cookie handling"""
        if cookies is not None:
            for c in cookies:
                c_key, c_value = str(cookies[c]).split(':', 1)
                self.handler.send_header(c_key, c_value.strip())
        resp_headers = resp.headers

        # Add CORS headers to allow cross-origin requests
        self.add_cors_headers()

        # Handle CSP headers - this can be overridden by subclasses
        self._handle_csp_headers(resp_headers)

        # Handle other headers
        for key in resp_headers:
            if key.lower() == 'content-security-policy':
                # CSP headers are handled in _handle_csp_headers
                continue
            elif key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding',
                             'transfer-encoding', 'content-length', 'Content-Length']:
                self.handler.send_header(key, resp_headers[key])

        # Only add Content-Length if it doesn't exist in original response
        # and we're not dealing with streaming content
        if 'Content-Length' not in resp_headers and 'content-length' not in resp_headers:
            # For streaming responses, don't add Content-Length
            if not resp.headers.get('Transfer-Encoding') == 'chunked':
                self.handler.send_header('Content-Length', str(len(resp.content)))
        else:
            # Preserve the original Content-Length
            content_length = resp_headers.get('Content-Length') or resp_headers.get('content-length')
            if content_length:
                self.handler.send_header('Content-Length', content_length)

        self.handler.end_headers()

    def _handle_csp_headers(self, resp_headers):
        """Handle CSP headers - can be overridden by subclasses for specific behavior"""
        for key in resp_headers:
            if key.lower() == 'content-security-policy':
                # Default behavior: preserve CSP headers as-is
                self.handler.send_header(key, resp_headers[key])

    def parse_headers(self):
        """Parse and prepare request headers for forwarding"""
        req_header = {}
        for i, j in self.handler.headers.items():
            req_header[i] = j
        req_header['X-Forwarded-For'] = common_vars.PROXY_CONTAINER_NAME
        if (self.user is not None and self.user != common_vars.DEFAULT_ADMIN_USER) or 'sessions' in self.handler.path:
            req_header['X-Forwarded-User'] = self.user
        return req_header

    def send_response_with_headers(self, resp):
        """Send response with proper headers and session handling"""
        self.handler.send_response(resp.status_code)
        if not self.get_auth_cookie_exist():
            # Check if user already has an active session (for session renewal)
            existing_session_id = session.get_session_id_by_username(self.user)

            if existing_session_id:
                # User has an existing session - use it (session renewal)
                logger.debug(f"Renewing existing session for user: {self.user} with session ID: {existing_session_id}")
                session_id = existing_session_id
            else:
                # User has no existing session - create new one
                logger.debug(f"Creating new session for user: {self.user}")
                session_id = session.create_new_session(self.user)
                logger.debug(f"Created session ID: {session_id} for user: {self.user}")

            c = SimpleCookie()
            c = self.set_cookie(c, self.common_params.cookie_name, session_id)
            self.send_resp_headers(resp, c)
        else:
            logger.debug(f"Using existing session for user: {self.user}")
            self.send_resp_headers(resp)

    def handle_cookie_authentication(self):
        """Handle cookie-based authentication"""
        logger.debug('Performing authorization')

        # Periodically cleanup expired sessions
        cleaned_count = session.cleanup_expired_sessions()
        if cleaned_count > 0:
            logger.debug(f"Cleaned up {cleaned_count} expired sessions")

        auth_cookie = self.get_cookie(self.common_params.cookie_name)
        self.set_auth_cookie_exist(False)

        if auth_cookie is not None and auth_cookie != '':
            user = session.get_username_by_session_id(auth_cookie)
            if user is None or not user:
                logger.debug(
                    f"There is no session assigned to this cookie: {auth_cookie}. Initialize new authorization process")
                return False
            self.set_user(user)
            self.set_auth_cookie_exist(True)
            logger.debug(
                f"Using session ID from cookie {self.common_params.cookie_name}: {auth_cookie} for user: {user}")
            return True
        else:
            logger.debug("There is no cookie in the request")
            return False


class OAuthHeaderHandler(HeaderHandler):
    """OAuth-specific header handler that extends base HeaderHandler"""

    def _handle_csp_headers(self, resp_headers):
        """Handle CSP headers to include OAuth provider URLs"""
        for key in resp_headers:
            if key.lower() == 'content-security-policy':
                csp_value = resp_headers[key]
                # Add OAuth provider URLs to connect-src directive
                if 'connect-src' in csp_value:
                    # Add OAuth provider domain to connect-src
                    oauth_domain = urlparse(self.auth_params.authorization_url).netloc
                    if oauth_domain not in csp_value:
                        # Replace connect-src directive to include OAuth domain
                        csp_value = re.sub(
                            r'(connect-src\s+[^;]+)',
                            r'\1 https://' + oauth_domain,
                            csp_value
                        )
                        logger.debug(f"Modified CSP header: {csp_value}")
                self.handler.send_header(key, csp_value)
