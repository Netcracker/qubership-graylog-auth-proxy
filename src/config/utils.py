import base64
from urllib.parse import urljoin

import common.log as log

logger = log.get_logger(__name__)


def str_to_bool(s: str) -> bool | None:
    s = s.lower()
    if s == 'true':
        return True
    if s == 'false':
        return False
    return None


def get_htpasswd(htpasswd_path):
    try:
        with open(htpasswd_path, 'rb') as hf:
            p = hf.read()
        return base64.b64decode(p).decode('utf-8')
    except Exception as e:
        logger.error(f'Error occurred during getting htpasswd content: {e}')


def get_password(plain_passwd, htpasswd):
    if htpasswd:
        return get_htpasswd(htpasswd)
    elif plain_passwd:
        return plain_passwd
    logger.error('Neither plain password / client secret nor htpasswd are set')
    return None


def get_http_url(host, path=None):
    if not host:
        return None
    url = host
    if path is not None and path:
        url = urljoin(host, path)
    return url
