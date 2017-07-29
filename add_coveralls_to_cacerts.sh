#!/bin/nash

openssl s_client -connect coveralls.io:443 -servername coveralls.io 2> /dev/null < /dev/null | openssl x509 > /tmp/coveralls.io.cer
keytool -import -v -trustcacerts -alias coveralls.io -file /tmp/coveralls.io.cer -keystore $JAVA_HOME/jre/lib/security/cacerts -keypass changeit -storepass changeit -noprompt
