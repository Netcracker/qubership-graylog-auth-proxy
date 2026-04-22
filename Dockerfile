FROM python:3.14.4-alpine3.23

COPY requirements.txt /etc/requirements.txt

WORKDIR /usr/src/app/

COPY src/ /usr/src/app/

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
