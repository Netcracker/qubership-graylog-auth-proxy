import os
from dataclasses import dataclass

import common.log as log
import common.vars as common_vars

logger = log.get_logger(__name__)


@dataclass
class CommonConfig:
    """Common configuration parameters"""
    cookie_name: str
    domain: str = "*"  # Default to allow all domains, user can set specific domain

    def __init__(self, host, port, metrics_port, tls_enabled, cert_path, key_path, cookie_name, domain="*",
                 access_control_max_age=common_vars.ACCESS_CONTROL_MAX_AGE,
                 cookie_max_age=common_vars.COOKIE_MAX_AGE,
                 cookie_expires_hours=common_vars.COOKIE_EXPIRES_HOURS,
                 session_expiration_time=common_vars.SESSION_EXPIRATION_TIME):
        self.proxy_host = host
        self.proxy_port = port
        self.proxy_metrics_port = metrics_port
        self.tls_enabled = tls_enabled.lower() == 'true'
        self.proxy_scheme = "http"
        if self.tls_enabled:
            self.proxy_scheme = "https"
        self.cert_path = cert_path
        self.key_path = key_path
        self.cookie_name = cookie_name
        self.domain = domain
        # Timing configuration
        self.access_control_max_age = access_control_max_age
        self.cookie_max_age = cookie_max_age
        self.cookie_expires_hours = cookie_expires_hours
        self.session_expiration_time = session_expiration_time

    def verify_config(self) -> bool:
        if self.cookie_name is None or not self.cookie_name:
            logger.error('Invalid common config: cookie name is empty')
            return False
        if self.tls_enabled:
            if self.cert_path is not None and self.cert_path:
                if not os.path.exists(self.cert_path):
                    logger.error('Invalid common config: Path to the certificate file for the proxy is incorrect')
                    return False
            else:
                logger.error('Invalid common config: Path to the certificate file for the proxy must not be empty '
                             'if the proxy is started in the secure mode')
                return False
            if self.key_path is not None and self.key_path:
                if not os.path.exists(self.key_path):
                    logger.error('Invalid common config: Path to the private key file for the proxy is incorrect')
                    return False
            else:
                logger.error('Invalid common config: Path to the private key file for the proxy must not be empty '
                             'if the proxy is started in the secure mode')
                return False
        return True
