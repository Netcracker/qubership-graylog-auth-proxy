import json
import secrets

import requests

import common.log as log
import common.vars as common_vars
from common.session import remove_existing_session
from config.graylog import GraylogConfig
from config.ldap import LDAPConfig
from ldap_auth_handler.ldap_connector import connect_ldap, find_user_in_ldap

logger = log.get_logger(__name__)


def rotate_passwords_in_graylog(graylog_params: GraylogConfig, ldap_params: LDAPConfig):
    try:
        put_headers = {
            'X-Requested-By': 'Graylog API Browser',
            'X-Forwarded-User': graylog_params.admin_user
        }
        get_headers = {
            'Accept': 'application/json',
            'X-Forwarded-User': graylog_params.admin_user
        }
        delete_headers = {
            'X-Requested-By': 'Graylog API Browser',
            'X-Forwarded-User': graylog_params.admin_user
        }
        pre_created_user_names = graylog_params.pre_created_users.split(',')
        resp_get = requests.get(graylog_params.url_get_users_list(), headers=get_headers,
                                verify=graylog_params.verify, cert=graylog_params.cert,
                                timeout=graylog_params.timeout)
        template = common_vars.TEMPLATES_ENV.get_template("new-password.json.j2")
        if resp_get.status_code == 200:
            ldap_object = connect_ldap(ldap_params)
            users_json_dict = json.loads(resp_get.text)
            for u in users_json_dict.get('users', []):
                uname = u.get('username', '')
                id = u.get('id', '')
                if uname not in pre_created_user_names:
                    if find_user_in_ldap(ldap_object, ldap_params, uname):
                        new_pass = secrets.token_urlsafe(32)
                        j = template.render(password=new_pass)
                        json_d = json.loads(j)
                        resp_put = requests.put(graylog_params.url_user_password(id),
                                                headers=put_headers, json=json_d,
                                                verify=graylog_params.verify, cert=graylog_params.cert,
                                                timeout=graylog_params.timeout)
                        if resp_put.status_code != 204:
                            logger.error(f'Error occurred during changing password for user {uname}')
                    else:
                        resp_delete = requests.delete(graylog_params.url_delete_user_by_id(id),
                                                      headers=delete_headers,
                                                      verify=graylog_params.verify, cert=graylog_params.cert,
                                                      timeout=graylog_params.timeout)
                        if resp_delete.status_code == 204:
                            remove_existing_session(uname)
                            logger.info(f'User {uname} has been deleted from Graylog because it can no longer be found '
                                        f'in LDAP')
                        elif resp_delete.status_code == 400:
                            logger.warn(f'Failed to delete read-only user {uname}: add it to pre-created-users list or '
                                        f'remove it manually')
                        else:
                            logger.error(f'Error occurred during deleting user {uname} with status code '
                                         f'{resp_delete.status_code}')
    except Exception as e:
        logger.error(f'Error occurred during password rotation: {e}')
