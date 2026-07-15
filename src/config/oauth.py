import os
from urllib.parse import urlparse

import common.log as log
from config.utils import get_http_url, get_password, str_to_bool

logger = log.get_logger(__name__)


class OAuthConfig:

    def __init__(self, host, authorization_path, token_path, userinfo_path, redirect_uri,
                 ca_cert_path, cert_path, key_path, insecure_skip_verify,
                 client_id, client_secret, htpasswd, scopes,
                 user_jsonpath, roles_jsonpath,
                 requests_timeout, technical_users_basic_auth="",
                 technical_users_static_tokens="", technical_users_roles=""):
        self.host = host
        self.scheme = urlparse(self.host).scheme
        # URLs for OAuth protocol
        self.authorization_url = get_http_url(host, path=authorization_path)
        self.token_url = get_http_url(host, path=token_path)
        self.userinfo_url = get_http_url(host, path=userinfo_path)
        self.redirect_uri = redirect_uri  # redirect_uri must include http:// or https://
        self.redirect_uri_path = urlparse(redirect_uri).path
        # SSL certificates
        self.ca_cert_path = ca_cert_path
        self.cert_path = cert_path
        self.key_path = key_path
        self.insecure_skip_verify = str_to_bool(insecure_skip_verify)
        # requests parameters
        self.timeout = requests_timeout
        self.verify = True
        if self.insecure_skip_verify:
            self.verify = False
        elif self.ca_cert_path is not None or self.ca_cert_path:
            self.verify = self.ca_cert_path
        self.cert = None
        if self.cert_path is not None and self.cert_path:
            if self.key_path is not None and self.key_path:
                self.cert = (self.cert_path, self.key_path)
            else:
                self.cert = self.cert_path
        self.client_id = client_id
        self.client_secret = get_password(client_secret, htpasswd)
        self.scopes = scopes
        self.user_jsonpath = user_jsonpath
        self.roles_jsonpath = roles_jsonpath

        # Technical users configuration (store as strings for the handler to parse)
        self.technical_users_basic_auth_str = technical_users_basic_auth
        self.technical_users_static_tokens_str = technical_users_static_tokens
        self.technical_users_roles_str = technical_users_roles

    def verify_config(self) -> bool:
        if self.scheme is None or not self.scheme or self.scheme not in ['http', 'https']:
            logger.error('Invalid OAuth2 config: attempt to use incorrect scheme for OAuth authorization server '
                         '(allowed only "http" or "https")')
            return False
        if self.host is None or not self.host:
            logger.error('Invalid OAuth2 config: OAuth authorization server host is empty')
            return False
        if self.scheme == 'https':
            if self.insecure_skip_verify:
                logger.warning('Skipping verification of certificates from OAuth authorization server is enabled')
            else:
                if self.ca_cert_path is None or not self.ca_cert_path:
                    logger.error('Invalid OAuth2 config: Set CA certificate if SSL connection is enabled')
                    return False
                if not os.path.exists(self.ca_cert_path):
                    logger.error('Invalid OAuth2 config: Path to the CA certificate is incorrect')
                    return False
            if self.cert_path is not None and self.cert_path:
                if not os.path.exists(self.cert_path):
                    logger.error('Invalid OAuth2 config: Path to the client certificate is incorrect')
                    return False
            if self.key_path is not None and self.key_path:
                if not os.path.exists(self.key_path):
                    logger.error('Invalid OAuth2 config: Path to the private key file is incorrect')
                    return False
                if self.cert_path is None and not self.cert_path:
                    logger.error('Invalid OAuth2 config: Private key cannot be used without the client certificate')
                    return False
        return True
