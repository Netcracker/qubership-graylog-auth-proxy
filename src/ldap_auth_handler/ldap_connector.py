import os

import ldap

import common.log as log
from config.ldap import LDAPConfig

logger = log.get_logger(__name__)
# Switch off processing .ldaprc or ldap.conf
os.environ['LDAPNOINIT'] = '1'


def connect_ldap(params: LDAPConfig) -> ldap.ldapobject.SimpleLDAPObject | None:

    # check that uri and baseDn are set
    # either from cli or a request
    if not params.url:
        logger.error('LDAP URL is not set!')
        return None
    if not params.basedn:
        logger.error('LDAP baseDN is not set!')
        return None

    ldap_obj = ldap.initialize(params.url)

    # Python-ldap module documentation advises to always
    # explicitly set the LDAP version to use after running
    # initialize() and recommends using LDAPv3. (LDAPv2 is
    # deprecated since 2003 as per RFC3494)
    #
    # Also, the STARTTLS extension requires the
    # use of LDAPv3 (RFC2830).
    ldap_obj.protocol_version = ldap.VERSION3

    ldap_obj.set_option(ldap.OPT_NETWORK_TIMEOUT, params.timeout)

    if params.disable_referrals:
        logger.debug('Referrals is disabled')
        ldap_obj.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)

    # STARTTLS or SSL
    if params.starttls or params.over_ssl:
        logger.debug('Try to establish connection with STARTTLS or over SSL')
        if params.insecure_skip_verify:
            # Skip verification if the parameter is set
            ldap_obj.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        else:
            # Force cert validation
            ldap_obj.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            # Set path name of file containing all trusted CA certificates
            logger.debug(f'CA certificate path: {params.ca_cert_path}')
            ldap_obj.set_option(ldap.OPT_X_TLS_CACERTFILE, params.ca_cert_path)
        if params.cert_path is not None and params.cert_path and params.key_path is not None and params.key_path:
            logger.debug(f'Client certificate file path: {params.cert_path}')
            ldap_obj.set_option(ldap.OPT_X_TLS_CERTFILE, params.cert_path)
            logger.debug(f'Private key file path: {params.key_path}')
            ldap_obj.set_option(ldap.OPT_X_TLS_KEYFILE, params.key_path)
        # Force libldap to create a new SSL context (must be last TLS option!)
        ldap_obj.set_option(ldap.OPT_X_TLS_NEWCTX, ldap.OPT_OFF)
        # Connection with STARTTLS
        if params.starttls:
            logger.debug('STARTTLS is enabled')
            ldap_obj.start_tls_s()

    ldap_obj.bind_s(params.binddn, params.bind_password, ldap.AUTH_SIMPLE)

    return ldap_obj


def find_user_in_ldap(ldap_o, params, user):
    search_filter = params.filter % {'username': user}
    results = ldap_o.search_s(params.basedn, ldap.SCOPE_SUBTREE, search_filter)
    if len(results) < 1:
        return False
    return True


def ldap_auth_handle(params: LDAPConfig, user: str, passwd: str) -> list | None:
    ldap_obj = connect_ldap(params)
    if ldap_obj is None:
        logger.error('LDAP object creation failed')
        return None

    logger.debug('Preparing search filter')
    search_filter = params.template % {'username': user}

    logger.info(f'Searching on server "{params.url}" with base dn "{params.basedn}" with filter "{search_filter}"')

    logger.debug('Running search query')
    results = ldap_obj.search_s(params.basedn, ldap.SCOPE_SUBTREE, search_filter)

    logger.debug('Verifying search query results')
    nres = len(results)

    if nres < 1:
        logger.error('No objects found in LDAP')
        return None
    if nres > 1:
        logger.warning(f"Filter match multiple objects: {nres}, using first")

    user_entry = results[0]
    ldap_dn = user_entry[0]
    member_of = user_entry[1].get('memberOf', [])

    if ldap_dn is None:
        logger.error('Matched object has no dn')
        return None

    logger.debug(f'Attempting to bind using dn "{ldap_dn}"')

    ldap_obj.bind_s(ldap_dn, passwd, ldap.AUTH_SIMPLE)

    logger.info(f'Auth OK for user "{user}"')

    return member_of
