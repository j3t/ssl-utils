package ssl;

/**
 * Constants with the names of the most common key store types.
 * 
 * @author j3t
 */
public interface KeyStoreType
{
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
