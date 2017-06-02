package com.github.j3t.ssl.utils.types;

/**
 * Constants with names of key store types.
 *
 * @author j3t
 */
public interface KeyStoreType {
    String WINDOWS_MY = "Windows-MY";
    String WINDOWS_ROOT = "Windows-ROOT";
    String PKCS11 = "PKCS11";
    String PKCS12 = "PKCS12";
    String JKS = "JKS";
    String DKS = "DKS";
    String BKS = "BKS";
    String JCEKS = "JCEKS";
    String KEYCHAIN_STORE = "KeychainStore";
}
