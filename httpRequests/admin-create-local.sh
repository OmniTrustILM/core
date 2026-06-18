#!/bin/bash

CERT=$(openssl pkcs12 -nokeys -clcerts -in ../ssl/client/client2.p12 -passin pass:123456)

NORM_CERT=$(echo "$CERT" | tail -n +6)
NORM_CERT=$(echo "$NORM_CERT" | sed -e 's/-----BEGIN CERTIFICATE-----//g' | sed -e 's/-----END CERTIFICATE-----//g' | sed -e 's/ //g' | sed ':a;N;$!ba;s/\n//g')

DATA="{ \"adminCertificate\": \"$NORM_CERT\", \"username\": \"local-superadmin\", \"name\": \"Local\", \"surname\": \"Admin\", \"email\": \"test@mail.io\" }"

curl -v -X POST \
 -H 'content-type: application/json' \
 -d "$DATA" \
 http://127.0.0.1:8080/api/v1/local/admins
