import json
import secrets

import requests

import common.log as log
import common.vars as common_vars
from common import mapping, stream_sharing
from config.graylog import GraylogConfig

logger = log.get_logger(__name__)


def graylog_handle(params: GraylogConfig, member_of, user):
    logger.info("Start work with Graylog users")
    logger.debug('Checking if the user is in Graylog')
    post_headers = {
        'X-Requested-By': 'Graylog API Browser',
        'X-Forwarded-User': params.admin_user
    }
    get_headers = {
        'Accept': 'application/json',
        'X-Forwarded-User': params.admin_user
    }
    passwd = secrets.token_urlsafe(32)
    roles = []
    streams = []
    if len(member_of) > 0:
        priority_role = common_vars.PRIORITY_ROLE_MAX  # just a big number
        priority_stream = common_vars.PRIORITY_STREAM_MAX  # just a big number
        for m_elem in member_of:
            member_of_decoded = m_elem
            if type(m_elem) is bytes or type(m_elem) is bytearray:
                member_of_decoded = member_of_decoded.decode("utf-8")
            # roles and streams with the least priority will be mapped
            roles_temp, priority_role_temp = mapping.role_mapping(params.role_mapping, member_of_decoded)
            if priority_role > priority_role_temp:
                roles, priority_role = roles_temp, priority_role_temp
            streams_temp, priority_stream_temp = mapping.stream_mapping(params.stream_mapping, member_of_decoded)
            if priority_stream > priority_stream_temp:
                streams, priority_stream = streams_temp, priority_stream_temp
        if len(roles) < 1:
            logger.info(f"No roles are matched for user \"{user}\", "
                        f"default roles {str(common_vars.DEFAULT_ROLES)} will be used")
            roles = common_vars.DEFAULT_ROLES
    else:
        logger.info(f"User \"{user}\" has empty memberOf field, "
                    f"default roles {str(common_vars.DEFAULT_ROLES)} will be used without sharing streams")
        roles = common_vars.DEFAULT_ROLES

    # getting and updating/creating a user
    resp_get = requests.get(params.url_get_user_by_name(user), headers=get_headers,
                            verify=params.verify, cert=params.cert, timeout=params.timeout)
    user_id = ''
    if resp_get.status_code == 404:
        logger.debug('Creating the user in Graylog')
        template_new_user = common_vars.TEMPLATES_ENV.get_template("new-graylog-user.json.j2")
        user_json = template_new_user.render(username=user,
                                             password=passwd,
                                             roles=roles).replace("'", '"')
        user_json_dict = json.loads(user_json)
        resp_post = requests.post(params.url_get_users_list(), headers=post_headers, json=user_json_dict,
                                  verify=params.verify, cert=params.cert, timeout=params.timeout)
        if resp_post.status_code == 201:
            logger.info(f'User "{user}" is created in Graylog')
        else:
            logger.error(f'Error occurred during creating user "{user}" in Graylog')
            return
    # else if user already exists
    elif resp_get.status_code == 200:
        if resp_get.content is None or not resp_get.content:
            logger.error('Response from Graylog includes incorrect JSON')
            return
        user_id = json.loads(resp_get.content).get('id', '')
        template_update_user = common_vars.TEMPLATES_ENV.get_template("update-graylog-user.json.j2")
        user_json = template_update_user.render(username=user, roles=roles).replace("'", '"')
        user_json_dict = json.loads(user_json)
        resp_put = requests.put(params.url_get_user_by_name(user_id), headers=post_headers, json=user_json_dict,
                                verify=params.verify, cert=params.cert, timeout=params.timeout)
        if resp_put.status_code != 204:
            logger.error(f'Error occurred during updating user in Graylog with code {resp_get.status_code}')
            return
    else:
        logger.error(f'Error occurred during API request to Graylog with code {resp_get.status_code}')
        return

    # streams sharing
    if not user_id:
        resp_get = requests.get(params.url_get_user_by_name(user), headers=get_headers,
                                verify=params.verify, cert=params.cert, timeout=params.timeout)
        if resp_get.status_code == 200:
            user_id = json.loads(resp_get.content).get('id', '')
        else:
            logger.error(f'Error occurred during getting user data with code {resp_get.status_code}')
            return
    streams_json = stream_sharing.get_streams(params)
    for stream_and_capability in streams:
        stream_sharing.share_stream(params,
                                    stream_sharing.get_stream_id(streams_json, stream_and_capability[0]),
                                    user_id,
                                    stream_and_capability[1])
