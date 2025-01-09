FROM python:3.13.0-alpine3.20

COPY graylog_auth_proxy.py /usr/src/app/
COPY common /usr/src/app/common
COPY config /usr/src/app/config
COPY ldap_auth_handler /usr/src/app/ldap_auth_handler
COPY oauth_handler /usr/src/app/oauth_handler
COPY templates /usr/src/app/templates
COPY requirements.txt /etc/requirements.txt
COPY pip.conf /etc/pip.conf

WORKDIR /usr/src/app/

# Install required software
RUN apk --no-cache add --upgrade \
        openldap-dev \
    && apk --no-cache add --upgrade --virtual \
        build-dependencies \
        build-base \
    && python3 -m pip install --upgrade \
        pip \
    && python3 -m pip install --no-cache-dir -r /etc/requirements.txt \
    && apk del build-dependencies

EXPOSE 8888
