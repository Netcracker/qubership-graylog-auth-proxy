#!/bin/bash
echo "Enter bind password for LDAP user: "
stty -echo
read -r passwd
stty echo
echo "$passwd" | base64 >"$1"
