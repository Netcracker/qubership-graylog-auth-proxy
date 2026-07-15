FROM python:3.14.4-alpine3.23

COPY requirements.txt /etc/requirements.txt

WORKDIR /usr/src/app/

COPY src/ /usr/src/app/

# Install required software
RUN apk --no-cache add --upgrade \
        "openldap-dev=2.6.10-r0" \
    && apk --no-cache add --upgrade --virtual \
        build-dependencies \
        "build-base=0.5-r3" \
    && python3 -m pip install --no-cache-dir --upgrade \
        "pip==26.0.1" \
    && python3 -m pip install --no-cache-dir -r /etc/requirements.txt \
    && apk del build-dependencies

EXPOSE 8888
