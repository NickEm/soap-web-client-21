#!/bin/bash
export KEYSTORE_FILENAME="src/main/resources/keystore/emsnewkeystore.jks"
export ALIAS="emsnewcert"
export KEYSTORE_PASSWORD="emsnewpassword"
export PRIVATE_KEY_PASSWORD="emsnewpassword"
export KEYSTORE_VALIDITY_DAYS="825"

keytool -genkey -alias "${ALIAS}" -keyalg RSA -keysize 2048 \
-keystore "${KEYSTORE_FILENAME}" -storepass "${KEYSTORE_PASSWORD}" -keypass "${PRIVATE_KEY_PASSWORD}" \
-dname "CN=localhost, OU=Home, O=Home, L=San Francisco, ST=California, C=US" \
-validity "${KEYSTORE_VALIDITY_DAYS}";

# Read generated keystore details
keytool -list -v -keystore "${KEYSTORE_FILENAME}" -storepass "${KEYSTORE_PASSWORD}"
