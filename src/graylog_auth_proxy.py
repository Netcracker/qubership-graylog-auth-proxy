import os
import signal
import ssl
import sys
import time
from http.server import HTTPServer

import configargparse as configargparse
import schedule
from prometheus_client import start_http_server

import common.log as log
from config.common_config import CommonConfig
from config.graylog import GraylogConfig
from config.ldap import LDAPConfig
from config.oauth import OAuthConfig
from ldap_auth_handler.handler import LDAPAuthHandler
from ldap_auth_handler.password_rotation import rotate_passwords_in_graylog
from oauth_handler.handler import OAuthHandler

if not hasattr(__builtins__, "basestring"):
    basestring = (str, bytes)

import threading
from socketserver import ThreadingMixIn

AUTH_TYPE_LDAP = 'ldap'
AUTH_TYPE_OAUTH = 'oauth'


class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass


# TODO: make password rotation for the OAuth mode
def run_schedulers(m, graylog_params, ldap_params):
    schedule.every(m).days.do(rotate_passwords_in_graylog, graylog_params, ldap_params)

    while True:
        schedule.run_pending()
        time.sleep(1)


def exit_handler(signal, frame):
    global Listen

    if isinstance(Listen, basestring):
        try:
            os.unlink(Listen)
        except Exception as e:
            ex, value, trace = sys.exc_info()
            sys.stderr.write(f'Failed to remove socket "{Listen}": {str(value)}\nException: {str(e)}')
            sys.stderr.flush()
    sys.exit(0)


if __name__ == '__main__':
    parser = configargparse.ArgParser(default_config_files=['./config.yaml'],
                                      config_file_parser_class=configargparse.YAMLConfigFileParser)
    parser.add_argument('--config',
                        default='config.yaml',
                        is_config_file=True,
                        help='Config file path')
    parser.add_argument('--auth-type',
                        required=True,
                        choices=[AUTH_TYPE_LDAP, AUTH_TYPE_OAUTH],
                        help="Defines which type of authentication protocol will be chosen (LDAP or OAuth 2.0). "
                             "LDAP and OAuth2 are mutually exclusive. Basic Auth for technical users works with both.")
    # Group for common options
    group = parser.add_argument_group("Common options")
    group.add_argument('--log-level', metavar="log_level",
                       default='INFO', help='Logging level. Allowed values: DEBUG, INFO, WARNING, ERROR, CRITICAL')
    group.add_argument('--host', metavar="hostname",
                       default="localhost", help="host to bind")
    group.add_argument('-p', '--port', metavar="port", type=int,
                       default=8888, help="port to bind")
    group.add_argument('--metrics-port', metavar="metrics_port", type=int,
                       default=8889, help="port for Prometheus metrics")
    group.add_argument('--proxy-tls-enabled', metavar="proxy_tls_enabled",
                       default="false", help="Run proxy in secure HTTPS mode")
    group.add_argument('--proxy-tls-cert-file', metavar="proxy_tls_cert_file",
                       default="", help="Path to certificate file for proxy HTTP server")
    group.add_argument('--proxy-tls-key-file', metavar="proxy_tls_key_file",
                       default="", help="Path to private key file for proxy HTTP server")
    group.add_argument('--cookie', metavar="cookiename",
                       default="authproxy", help="HTTP cookie name to set in")
    group.add_argument('--domain', metavar="domain",
                       default="*", help="Domain for CORS Access-Control-Allow-Origin header (use '*' for all domains)")
    group.add_argument('--access-control-max-age', metavar="access_control_max_age",
                       type=int,
                       default=86400,
                       help="Max age for CORS preflight requests in seconds (default: 86400 = 24 hours)")
    group.add_argument('--cookie-max-age', metavar="cookie_max_age",
                       type=int,
                       default=86400,
                       help="Max age for session cookies in seconds (default: 86400 = 24 hours)")
    group.add_argument('--cookie-expires-hours', metavar="cookie_expires_hours",
                       type=float,
                       default=24.0,
                       help="Cookie expiration time in hours (default: 24.0 hours)")
    group.add_argument('--session-expiration-time', metavar="session_expiration_time",
                       type=int,
                       default=86400,
                       help="Session expiration time in seconds (default: 86400 = 24 hours)")
    group.add_argument('--requests-timeout', metavar='requests_timeout',
                       type=float,
                       default=30,
                       help="A global parameter describes how many seconds to wait for the server to send data "
                            "before giving up")

    # LDAP options
    group = parser.add_argument_group(title="LDAP options")
    group.add_argument('--ldap-url', metavar="ldap_url",
                       default="ldap://127.0.0.1:389",
                       help="LDAP URI to query")
    group.add_argument('--http-realm', metavar='http_realm',
                       default="Restricted", help='HTTP auth realm')
    group.add_argument('--ldap-starttls', metavar="ldap_starttls",
                       default="false",
                       help="Establish a STARTTLS protected session for connection to LDAP server")
    group.add_argument('--ldap-over-ssl', metavar="ldap_over_ssl",
                       default="false",
                       help="Establish LDAP session over SSL")
    group.add_argument('--disable-referrals', metavar="disable_referrals",
                       default="false",
                       help="Sets ldap.OPT_REFERRALS to zero")
    group.add_argument('-b', '--base-dn', metavar="baseDn", dest="basedn", default='',
                       help="LDAP base DN")
    group.add_argument('-D', '--bind-dn', metavar="bindDn", dest="binddn", default='',
                       help="LDAP bind DN")
    group.add_argument('-w', '--bind-password', metavar="password", dest="bindpw", default='',
                       help="LDAP password for the bind DN")
    group.add_argument('--htpasswd', metavar="htpasswd", dest="htpasswd", default='',
                       help="Path to htpasswd file with LDAP password for the bind DN in Base64 format")
    group.add_argument('-f', '--filter', metavar='filter',
                       default='(cn=%(username)s)',
                       help="LDAP filter")

    # Graylog options
    group = parser.add_argument_group(title="Graylog options")
    group.add_argument('--role-mapping', metavar='role_mapping',
                       default='',
                       help="Filter for mapping Graylog roles between LDAP and Graylog users by memberOf field")
    group.add_argument('--stream-mapping', metavar='stream_mapping',
                       default='',
                       help="Filter for sharing Graylog streams between LDAP and Graylog users by memberOf field")

    group.add_argument('--graylog-pre-created-users', metavar='graylog_pre_created_users',
                       default='admin,auditViewer,operator,telegraf_operator,graylog-sidecar,graylog_api_th_user',
                       help="Comma separated pre-created users in Graylog for which you do not need "
                            "to rotate passwords")
    group.add_argument('--graylog-host', metavar='graylog_host',
                       default='http://127.0.0.1:9000',
                       help="Graylog host")
    group.add_argument('--graylog-tls-insecure-skip-verify', metavar="graylog_tls_insecure_skip_verify",
                       default="false",
                       help="Allows skipping verification of certificate from Graylog server")
    group.add_argument('--graylog-tls-ca-file', metavar="graylog_tls_ca_file",
                       default='',
                       help="Path to CA certificate file for connection to Graylog")
    group.add_argument('--graylog-tls-cert-file', metavar="graylog_tls_cert_file",
                       default='',
                       help="Path to client certificate file for connection to Graylog")
    group.add_argument('--graylog-tls-key-file', metavar="graylog_tls_key_file",
                       default='',
                       help="Path to private key file for connection to Graylog")
    group.add_argument('--graylog-admin-user', metavar='graylog_admin_user',
                       default='graylog_api_th_user',
                       help="Existed Graylog with admin rights")
    group.add_argument('--rotation-pass-interval', metavar='rotation_pass_interval',
                       type=int,
                       default=3,
                       help="Interval in days between password rotation for non-pre-created users")

    # OAuth2 options
    group = parser.add_argument_group(title="OAuth2 options")
    group.add_argument('--oauth-host', metavar='oauth_host',
                       default='http://127.0.0.1:8080',
                       help="OAuth2 authorization server host")
    group.add_argument('--oauth-authorization-path', metavar='oauth_authorization_path',
                       default='',
                       help="This path will be used to build URL for redirection "
                            "to OAuth2 authorization server login page")
    group.add_argument('--oauth-token-path', metavar='oauth_token_path',
                       default='',
                       help="This path will be used to build URL for getting auth token "
                            "from OAuth2 authorization server")
    group.add_argument('--oauth-userinfo-path', metavar='oauth_userinfo_path',
                       default='',
                       help="This path will be used to build URL for getting information about current user "
                            "from OAuth2 authorization server "
                            "to get username and entities (roles, groups, etc.) for Graylog roles and streams mapping")
    group.add_argument('--oauth-redirect-uri', metavar='oauth_redirect_uri',
                       default='http://localhost:8888/code',
                       help="URI to redirect after successful logging in "
                            "on OAuth2 authorization server side")
    group.add_argument('--oauth-client-id', metavar="oauth_client_id",
                       default='graylog-auth-proxy',
                       help="OAuth2 Client ID for the proxy")
    group.add_argument('--oauth-client-secret', metavar="oauth_client_secret",
                       default='',
                       help="OAuth2 Client Secret for the proxy")
    group.add_argument('--oauth-htpasswd', metavar="oauth_htpasswd", dest="oauth_htpasswd", default='',
                       help="Path to htpasswd file with Client Secret for the OAuth2 protocol in Base64 format")
    group.add_argument('--oauth-scopes', metavar="oauth_scopes",
                       default='openid profile roles',
                       help="OAuth2 scopes for the proxy separated by spaces. "
                            "Configured for Keycloak server by default")
    group.add_argument('--oauth-user-jsonpath', metavar="oauth_user_jsonpath",
                       default='preferred_username',
                       help="JSONPath (by jsonpath-ng) for taking username "
                            "from the JSON returned from OAuth2 server by using userinfo path. "
                            "Configured for Keycloak server by default")
    group.add_argument('--oauth-roles-jsonpath', metavar="oauth_roles_jsonpath",
                       default='realm_access.roles[*]',
                       help="JSONPath (by jsonpath-ng) for taking information about entities (roles, groups, etc.) "
                            "for Graylog roles and streams mapping "
                            "from the JSON returned from OAuth2 server by using userinfo path. "
                            "Configured for Keycloak server by default")

    # Technical users options (Basic Auth and Static Tokens)
    group = parser.add_argument_group(title="Technical users options")
    group.add_argument('--technical-users-basic-auth', metavar="technical_users_basic_auth",
                       default='',
                       help="Comma-separated list of technical users allowed to use Basic Auth "
                            "in format 'username:password,username2:password2'. "
                            "These users bypass OAuth flow and can authenticate directly.")
    group.add_argument('--technical-users-static-tokens', metavar="technical_users_static_tokens",
                       default='',
                       help="Comma-separated list of technical users with static tokens "
                            "in format 'username:token,username2:token2'. "
                            "These users can authenticate using Authorization: Bearer <token> header.")
    group.add_argument('--technical-users-roles', metavar="technical_users_roles",
                       default='',
                       help="Comma-separated list of roles assigned to technical users "
                            "in format 'username:role1,role2;username2:role1'. "
                            "If not specified, technical users get default roles.")

    # Auth provider TLS options
    group.add_argument('--auth-tls-insecure-skip-verify', metavar="auth_tls_insecure_skip_verify",
                       default="false",
                       help="Allows skipping verification of certificate "
                            "from LDAP server or OAuth authentication server")
    group.add_argument('--auth-tls-ca-file', metavar="auth_tls_ca_file",
                       default='',
                       help="Path to CA certificate file for LDAP server or OAuth authentication server")
    group.add_argument('--auth-tls-cert-file', metavar="auth_tls_cert_file",
                       default='',
                       help="Path to client certificate file for LDAP server or OAuth authentication server")
    group.add_argument('--auth-tls-key-file', metavar="auth_tls_key_file",
                       default='',
                       help="Path to private key file for LDAP server or OAuth authentication server")

    args = parser.parse_args()

    log.set_log_level(args.log_level)
    logger = log.get_logger(__name__)
    logger.setLevel(args.log_level)

    common_config = CommonConfig(args.host,
                                 args.port,
                                 args.metrics_port,
                                 args.proxy_tls_enabled,
                                 args.proxy_tls_cert_file,
                                 args.proxy_tls_key_file,
                                 args.cookie,
                                 args.domain,
                                 args.access_control_max_age,
                                 args.cookie_max_age,
                                 args.cookie_expires_hours,
                                 args.session_expiration_time)
    if not common_config.verify_config():
        sys.exit(1)

    # Configure session expiration time from config
    import common.session as session
    session.set_session_expiration_time(common_config.session_expiration_time)
    graylog_config = GraylogConfig(args.graylog_host,
                                   args.graylog_tls_ca_file,
                                   args.graylog_tls_cert_file,
                                   args.graylog_tls_key_file,
                                   args.graylog_tls_insecure_skip_verify,
                                   args.graylog_admin_user,
                                   args.graylog_pre_created_users,
                                   args.role_mapping,
                                   args.stream_mapping,
                                   args.requests_timeout)
    if not graylog_config.verify_config():
        sys.exit(1)
    if args.auth_type == AUTH_TYPE_LDAP:
        auth_config = LDAPConfig(args.ldap_url,
                                 args.ldap_starttls,
                                 args.ldap_over_ssl,
                                 args.auth_tls_ca_file,
                                 args.auth_tls_cert_file,
                                 args.auth_tls_key_file,
                                 args.auth_tls_insecure_skip_verify,
                                 args.disable_referrals,
                                 args.basedn,
                                 args.filter,
                                 args.binddn,
                                 args.bindpw,
                                 args.htpasswd,
                                 args.http_realm,
                                 args.requests_timeout,
                                 args.technical_users_basic_auth,
                                 args.technical_users_static_tokens,
                                 args.technical_users_roles)
        handler = LDAPAuthHandler
        if not auth_config.verify_config():
            sys.exit(1)
        d = threading.Thread(target=run_schedulers,
                             args=(args.rotation_pass_interval, graylog_config, auth_config,),
                             name='Daemon')
        d.daemon = True
        d.start()
    elif args.auth_type == AUTH_TYPE_OAUTH:
        auth_config = OAuthConfig(args.oauth_host,
                                  args.oauth_authorization_path,
                                  args.oauth_token_path,
                                  args.oauth_userinfo_path,
                                  args.oauth_redirect_uri,
                                  args.auth_tls_ca_file,
                                  args.auth_tls_cert_file,
                                  args.auth_tls_key_file,
                                  args.auth_tls_insecure_skip_verify,
                                  args.oauth_client_id,
                                  args.oauth_client_secret,
                                  args.oauth_htpasswd,
                                  args.oauth_scopes,
                                  args.oauth_user_jsonpath,
                                  args.oauth_roles_jsonpath,
                                  args.requests_timeout,
                                  args.technical_users_basic_auth,
                                  args.technical_users_static_tokens,
                                  args.technical_users_roles)
        handler = OAuthHandler
        if not auth_config.verify_config():
            sys.exit(1)

    handler.set_common_params(common_config)
    handler.set_auth_params(auth_config)
    handler.set_graylog_params(graylog_config)
    Listen = (common_config.proxy_host, common_config.proxy_port)
    server = AuthHTTPServer(Listen, handler)
    if common_config.tls_enabled:
        sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslcontext.load_cert_chain(certfile=common_config.cert_path, keyfile=common_config.key_path)
        server.socket = sslcontext.wrap_socket(server.socket, server_side=True)

    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

    logger.info(f"Start listening on {common_config.proxy_host}:{common_config.proxy_port}...")
    logger.info(f"Prometheus metrics are available on"
                f" {common_config.proxy_host}:{common_config.proxy_metrics_port}...")
    start_http_server(addr=common_config.proxy_host, port=common_config.proxy_metrics_port)
    sys.stdout.flush()
    server.serve_forever()
