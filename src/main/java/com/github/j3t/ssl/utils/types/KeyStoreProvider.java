package com.github.j3t.ssl.utils.types;


/**
 * Constants with names of key store providers.
 *
 * @author j3t
 */
public interface KeyStoreProvider {
    String SUN_PKCS11 = "SunPKCS11";
    String SUN = "SUN";
    String SUN_RSA_SIGN = "SunRsaSign";
    String SUN_JSSE = "SunJSSE";
    String SUN_JCE = "SunJCE";
    String SUN_JGSS = "SunJGSS";
    String SUN_SASL = "SunSASL";
    String XMLD_SIG = "XMLDSig";
    String SUN_PCSC = "SunPCSC";
    String SUN_MSCAPI = "SunMSCAPI";
    String SUN_EC = "SunEC";
    String ORACLE_UCRYPTO = "OracleUcrypto";
    String APPLE = "Apple";
}
