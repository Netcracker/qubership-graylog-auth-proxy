import base64
import logging
import time
import warnings
from http.server import BaseHTTPRequestHandler
from urllib.parse import urljoin

import requests
from ldap.filter import escape_filter_chars
from urllib3.exceptions import InsecureRequestWarning

import common.log as log
import common.session as session
import common.vars as common_vars
from common.graylog import graylog_handle
from common.headers import HeaderHandler
from config.common_config import CommonConfig
from config.graylog import GraylogConfig
from config.ldap import LDAPConfig
from ldap_auth_handler.ldap_connector import ldap_auth_handle
from basic_auth_handler import BasicAuthHandler, BasicAuthConfig

# Suppress InsecureRequestWarning for development/testing environments
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

logger = log.get_logger(__name__)
logging.getLogger("urllib3").setLevel(logging.ERROR)


class LDAPAuthHandler(BaseHTTPRequestHandler):

    @classmethod
    def set_common_params(cls, params: CommonConfig):
        cls.common_params = params

    def get_common_params(self) -> CommonConfig:
        return self.common_params

    @classmethod
    def set_auth_params(cls, params: LDAPConfig):
        cls.ldap_params = params

    def get_auth_params(self) -> LDAPConfig:
        return self.ldap_params

    @classmethod
    def set_graylog_params(cls, params: GraylogConfig):
        cls.graylog_params = params

    def get_graylog_params(self) -> GraylogConfig:
        return self.graylog_params

    @classmethod
    def set_user(cls, user: str):
        cls.user = user

    def get_user(self) -> str:
        return self.user

    @classmethod
    def set_passwd(cls, passwd: str):
        cls.passwd = passwd

    def get_passwd(self) -> str:
        return self.passwd

    @classmethod
    def set_auth_cookie_exist(cls, auth_cookie_exist: bool):
        cls.auth_cookie_exist = auth_cookie_exist

    def get_auth_cookie_exist(self) -> bool:
        return self.auth_cookie_exist

    def set_technical_user_authenticated(self, value: bool):
        self._technical_user_authenticated = value

    def get_technical_user_authenticated(self) -> bool:
        return self._technical_user_authenticated

    def __init__(self, *args, **kwargs):
        self._technical_user_authenticated = False
        super().__init__(*args, **kwargs)
        # Initialize header_handler lazily to avoid issues during class setup
        self._header_handler = None

    def _ensure_header_handler(self):
        """Ensure header_handler is initialized"""
        if not hasattr(self, '_header_handler') or self._header_handler is None:
            self._header_handler = self._get_header_handler()
        return self._header_handler

    @property
    def header_handler(self):
        """Lazy initialization of header handler"""
        return self._ensure_header_handler()

    def _get_header_handler(self):
        """Get or create the header handler instance"""
        # Check if class parameters are set before creating header handler
        if not hasattr(self.__class__, 'common_params') or not hasattr(self.__class__, 'ldap_params') \
                or not hasattr(self.__class__, 'graylog_params'):
            raise RuntimeError(
                "Header handler parameters not set."
                " Call set_common_params(), set_auth_params(), and set_graylog_params() first.")
        return HeaderHandler(
            self,
            self.get_common_params(),
            self.get_auth_params(),
            self.get_graylog_params())

    def get_cookie(self, name):
        return self.header_handler.get_cookie(name)

    def set_cookie(self, cookie, cookie_name, cookie_value, max_age=None, expires_hours=None):
        return self.header_handler.set_cookie(cookie, cookie_name, cookie_value, max_age, expires_hours)

    def add_cors_headers(self):
        return self.header_handler.add_cors_headers()

    def add_cors_headers_with_cache(self):
        return self.header_handler.add_cors_headers_with_cache()

    def get_cors_origin_header(self):
        return self.header_handler.get_cors_origin_header()

    def send_resp_headers(self, resp, cookies=None):
        return self.header_handler.send_resp_headers(resp, cookies)

    def parse_headers(self):
        req_header = self.header_handler.parse_headers()
        # LDAP-specific: remove Authorization headers
        if self.user != common_vars.DEFAULT_ADMIN_USER or 'sessions' in self.path:
            req_header.pop('Authorization', None)
            req_header.pop('authorization', None)
        return req_header

    def send_response_with_headers(self, resp):
        return self.header_handler.send_response_with_headers(resp)

    def auth_handle(self):
        logger.debug('Performing authorization')

        # Periodically cleanup expired sessions
        cleaned_count = session.cleanup_expired_sessions()
        if cleaned_count > 0:
            logger.debug(f"Cleaned up {cleaned_count} expired sessions")

        auth_header = self.headers.get('Authorization')
        auth_cookie = self.get_cookie(self.common_params.cookie_name)
        self.set_auth_cookie_exist(False)
        self.set_technical_user_authenticated(False)

        # Try technical users authentication FIRST (highest priority)
        if auth_header is not None and auth_header:
            technical_users_config = BasicAuthConfig.from_strings(
                self.ldap_params.technical_users_basic_auth_str,
                self.ldap_params.technical_users_static_tokens_str,
                self.ldap_params.technical_users_roles_str
            )

            technical_users_handler = BasicAuthHandler(
                technical_users_config,
                self.graylog_params,
                self.common_params
            )

            result = technical_users_handler.handle_authentication(
                auth_header,
                self.set_user,
                self.get_user
            )

            if result:
                # Technical users bypass session management and LDAP auth
                self.set_technical_user_authenticated(True)
                logger.debug(f"Technical user {self.get_user()} authenticated, bypassing session management")
                return True

        # For non-technical users, try cookie-based authentication
        if auth_cookie is not None and auth_cookie != '':
            auth_header = session.get_username_by_session_id(auth_cookie)
            self.set_auth_cookie_exist(True)
            logger.debug(f"Using session ID from cookie {self.common_params.cookie_name}")
        else:
            logger.debug("Using username/password from authorization header")

        if self.auth_cookie_exist:
            self.set_user(auth_header)
            # Continue request processing with username found by session ID
            return True

        # Fall back to LDAP authentication
        if auth_header is None or not auth_header.lower().startswith('basic '):
            self.send_response(401)
            self.send_header('WWW-Authenticate', f'Basic realm="{self.ldap_params.realm}"')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            return False

        logger.debug('Decoding credentials')

        try:
            auth_decoded = base64.b64decode(auth_header[6:])
            auth_decoded = auth_decoded.decode("utf-8")
            user, passwd = auth_decoded.split(':', 1)
        except Exception as e:
            self.auth_failed(str(e))
            return False

        self.set_user(escape_filter_chars(user))
        self.set_passwd(passwd)

        # Continue request processing
        return True

    def auth_and_graylog_handle(self):
        logger.debug('Initializing basic auth handler')
        if not self.auth_handle():
            # request already processed, auth wasn't successful
            return False
        # Technical users already authenticated and handled Graylog in BasicAuthHandler
        if self.get_technical_user_authenticated():
            return True
        # LDAP auth, creating/updating of users and sharing of streams happen only for the first time in a session
        # and only for not a default Graylog admin user
        if self.user != common_vars.DEFAULT_ADMIN_USER and not self.auth_cookie_exist:
            member_of = ldap_auth_handle(self.ldap_params, self.user, self.passwd)
            if member_of is None or not member_of:
                self.auth_failed()
                return False
            graylog_handle(self.graylog_params, member_of, self.user)
        elif self.user == common_vars.DEFAULT_ADMIN_USER:
            logger.debug('Log in as default admin user: skip LDAP authentication')
        return True

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        logger.debug(f"Start OPTIONS handling: {self.path}")

        # Check if this is a request that would trigger authentication
        # if self.path == '/' or self.path.startswith('/search') or self.path.startswith('/api'):
        #     # This could be a request that would trigger authentication
        #     # Send CORS headers for preflight requests
        #     self.send_response(200)
        #     self.add_cors_headers_with_cache()
        #     self.end_headers()
        #     return

        # For other paths, let the normal flow handle it
        self.send_response(200)
        self.add_cors_headers_with_cache()
        self.end_headers()
        return

    def do_HEAD(self):
        self.do_GET(body=False)
        return

    def do_GET(self, body=True):
        logger.debug(f"Start GET handling: {self.path}")
        start_time = time.time()
        try:
            if not self.auth_and_graylog_handle():
                return

            # Successfully authenticated user
            logger.debug('Trying to proxy to Graylog')
            req_headers = self.parse_headers()
            resp = requests.get(
                urljoin(self.graylog_params.url, self.path),
                headers=req_headers,
                verify=self.graylog_params.verify,
                cert=self.graylog_params.cert,
                timeout=self.graylog_params.timeout,
                stream=True
            )
            self.send_response_with_headers(resp)
            if body:
                # Use resp.content instead of resp.text to avoid corrupting binary files
                self.wfile.write(resp.content)
        except Exception as e:
            self.auth_failed(str(e))
        current_exec_time = time.time() - start_time
        logger.debug(f'GET execution time: {current_exec_time}')
        common_vars.GET_REQUEST_DURATION.observe(current_exec_time)
        return

    def do_POST(self):
        logger.debug(f"Start POST handling: {self.path}")
        start_time = time.time()
        try:
            if not self.auth_and_graylog_handle():
                return

            # Successfully authenticated user
            logger.debug('Trying to proxy to Graylog')
            content_len = int(self.headers.get('content-length', 0))
            post_body = self.rfile.read(content_len)
            req_headers = self.parse_headers()
            resp = requests.post(
                urljoin(self.graylog_params.url, self.path),
                headers=req_headers, data=post_body,
                verify=self.graylog_params.verify,
                cert=self.graylog_params.cert,
                timeout=self.graylog_params.timeout,
                stream=True
            )
            self.send_response_with_headers(resp)
            self.wfile.write(resp.content)
        except Exception as e:
            self.auth_failed(str(e))
        current_exec_time = time.time() - start_time
        logger.debug(f'POST execution time: {current_exec_time}')
        common_vars.POST_REQUEST_DURATION.observe(current_exec_time)
        return

    def do_PUT(self):
        logger.debug(f"Start PUT handling: {self.path}")
        start_time = time.time()
        try:
            if not self.auth_and_graylog_handle():
                return

            # Successfully authenticated user
            logger.debug('Trying to proxy to Graylog')
            content_len = int(self.headers.get('content-length', 0))
            put_body = self.rfile.read(content_len)
            req_headers = self.parse_headers()
            resp = requests.put(
                urljoin(self.graylog_params.url, self.path),
                headers=req_headers, data=put_body,
                verify=self.graylog_params.verify,
                cert=self.graylog_params.cert,
                timeout=self.graylog_params.timeout,
                stream=True
            )
            self.send_response_with_headers(resp)
            self.wfile.write(resp.content)
        except Exception as e:
            self.auth_failed(str(e))
        current_exec_time = time.time() - start_time
        logger.debug(f'PUT execution time: {current_exec_time}')
        common_vars.PUT_REQUEST_DURATION.observe(current_exec_time)
        return

    def do_DELETE(self):
        logger.debug(f"Start DELETE handling: {self.path}")
        start_time = time.time()
        try:
            if not self.auth_and_graylog_handle():
                return

            # Successfully authenticated user
            logger.debug('Trying to proxy to Graylog')
            content_len = int(self.headers.get('content-length', 0))
            delete_body = self.rfile.read(content_len)
            req_headers = self.parse_headers()
            resp = requests.delete(
                urljoin(self.graylog_params.url, self.path), headers=req_headers, data=delete_body,
                verify=self.graylog_params.verify,
                cert=self.graylog_params.cert,
                timeout=self.graylog_params.timeout,
                stream=True)
            self.send_response_with_headers(resp)
            self.wfile.write(resp.content)
        except Exception as e:
            self.auth_failed(str(e))
        current_exec_time = time.time() - start_time
        logger.debug(f'DELETE execution time: {current_exec_time}')
        common_vars.DELETE_REQUEST_DURATION.observe(current_exec_time)
        return

    # Log the error and complete the request with appropriate status
    def auth_failed(self, errmsg=None):
        if errmsg is not None:
            msg = f'Raised exception: {errmsg}'
        else:
            msg = 'Authentication failed'
        if self.graylog_params.url is not None and self.graylog_params.url:
            msg += f', Graylog url: {self.graylog_params.url}'
        if self.ldap_params.url is not None and self.ldap_params.url:
            msg += f', LDAP url: {self.ldap_params.url}'
        if self.user is not None and self.user:
            msg += f', user: {self.user}'
        logger.error(msg)
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="' + self.ldap_params.realm + '"')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
