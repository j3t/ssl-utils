
package ssl;


import java.security.cert.X509Certificate;

/**
 * Constants representing the key usages extension of x509 certificates. The key usage extension defines the purpose (e.g.,
 * encipherment, signature, certificate signing) of the key contained in the certificate.
 * 
 * @see X509Certificate#getKeyUsage()
 * 
 * @author j3t
 */
public enum KeyUsage
{
    DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT, KEY_AGREEMENT, KEY_CERT_SIGN, C_RL_SIGN,
    ENCIPHER_ONLY, DECIPHER_ONLY;
}
