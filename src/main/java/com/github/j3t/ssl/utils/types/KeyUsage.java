package com.github.j3t.ssl.utils.types;


import java.security.cert.X509Certificate;

/**
 * Constants representing the key usages extension of x509 certificates. The key usage extension defines the purpose (e.g.,
 * encipherment, signature, certificate signing) of the key contained in the certificate.
 *
 * @author j3t
 * @see X509Certificate#getKeyUsage()
 */
public enum KeyUsage {
    DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT, KEY_AGREEMENT, KEY_CERT_SIGN, C_RL_SIGN,
    ENCIPHER_ONLY, DECIPHER_ONLY
}
