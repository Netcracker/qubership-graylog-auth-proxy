#!/bin/bash

echo -n "Enter .htpasswd path (default test/.htpasswd): "
read path || path="test/.htpasswd"

echo -n "Enter user name (default 'admin'): "
read username

echo -n "Enter user password (default 'admin'): "
stty -echo
read password
stty echo

if [ -z "${path}" ]; then
    path="test/.htpasswd"
fi

if [ -z "${username}" ]; then
    username="admin"
fi

if [ -z "${password}" ]; then
    password="admin"
fi

if [ ! -f ${path} ]; then
    echo "The .htpasswd by specified password doesn't exist, so it will create"
    htpasswd -b -c ${path} ${username} ${password}
else
    echo "The .htpasswd by specified password already exist, so it will update"
    htpasswd -b ${path} ${username} ${password}
fi
