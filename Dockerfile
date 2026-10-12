FROM python:3.14.8-alpine3.24@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

COPY requirements.txt /etc/requirements.txt

WORKDIR /usr/src/app/

COPY src/ /usr/src/app/

# Install required software
# renovate: datasource=repology depName=alpine_3_24/openldap versioning=apk
RUN apk --no-cache upgrade \
    && apk --no-cache add \
        "openldap-dev=2.6.15-r0" \
    && apk --no-cache add --virtual \
        build-dependencies \
        "build-base=0.5-r4" \
    && python3 -m pip install --no-cache-dir --upgrade \
        "pip==26.2.1" \
    && python3 -m pip install --no-cache-dir -r /etc/requirements.txt \
    && apk del build-dependencies

EXPOSE 8888
