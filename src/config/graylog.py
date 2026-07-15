import os
from urllib.parse import urljoin, urlparse

import common.log as log
from common.vars import (GRAYLOG_API_STREAMS, GRAYLOG_API_USERS,
                         GRAYLOG_API_USERS_ID)
from config.utils import get_http_url, str_to_bool

logger = log.get_logger(__name__)


class GraylogConfig:

    def __init__(self, host,
                 ca_cert_path, cert_path, key_path, insecure_skip_verify,
                 admin_user, pre_created_users, role_mapping, stream_mapping,
                 requests_timeout):
        self.host = host
        self.scheme = urlparse(self.host).scheme
        self.url = get_http_url(host)
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
        self.admin_user = admin_user
        self.pre_created_users = pre_created_users
        self.role_mapping = role_mapping
        self.stream_mapping = stream_mapping

    def verify_config(self) -> bool:
        if self.scheme is None or not self.scheme or self.scheme not in ['http', 'https']:
            logger.error('Invalid Graylog config: attempt to use incorrect scheme for Graylog '
                         '(allowed only "http" or "https")')
            return False
        if self.host is None or not self.host:
            logger.error('Invalid Graylog config: Graylog host is empty')
            return False
        if self.admin_user is None or not self.admin_user:
            logger.error('Invalid Graylog config: admin user is empty')
            return False
        if self.scheme == 'https':
            if self.insecure_skip_verify:
                logger.warning('Skipping verification of certificates from Graylog server is enabled')
            else:
                if self.ca_cert_path is None or not self.ca_cert_path:
                    logger.error('Invalid Graylog config: Set CA certificate if SSL connection is enabled')
                    return False
                if not os.path.exists(self.ca_cert_path):
                    logger.error('Invalid Graylog config: Path to the CA certificate is incorrect')
                    return False
            if self.cert_path is not None and self.cert_path:
                if not os.path.exists(self.cert_path):
                    logger.error('Invalid Graylog config: Path to the client certificate is incorrect')
                    return False
            if self.key_path is not None and self.key_path:
                if not os.path.exists(self.key_path):
                    logger.error('Invalid Graylog config: Path to the private key file is incorrect')
                    return False
                if self.cert_path is None and not self.cert_path:
                    logger.error('Invalid Graylog config: Private key cannot be used without the client certificate')
                    return False
        return True

    def url_get_users_list(self):
        return urljoin(self.url, GRAYLOG_API_USERS)

    def url_get_user_by_name(self, user):
        return urljoin(urljoin(self.url, GRAYLOG_API_USERS), user)

    def url_user_password(self, user_id):
        return urljoin(urljoin(urljoin(self.url, GRAYLOG_API_USERS), user_id), '/password')

    def url_delete_user_by_id(self, user_id):
        return urljoin(urljoin(self.url, GRAYLOG_API_USERS_ID), user_id)

    def url_get_streams(self):
        return urljoin(self.url, GRAYLOG_API_STREAMS)

    def url_stream_share(self, stream_id):
        return urljoin(self.url, f'/api/authz/shares/entities/grn::::stream:{stream_id}')
