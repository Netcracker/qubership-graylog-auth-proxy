FROM python:3.15.2-alpine3.24@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211

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
