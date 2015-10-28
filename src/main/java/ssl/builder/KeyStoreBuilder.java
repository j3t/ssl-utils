
package ssl.builder;


import static ssl.KeyStoreType.PKCS11;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.UUID;

import ssl.KeyStoreProvider;
import ssl.KeyStoreType;

/**
 * A builder pattern style {@link KeyStore} factory with PKI.
 * 
 * @author j3t
 */
public class KeyStoreBuilder
{
    protected String type;
    protected String provider;
    protected String path;
    protected boolean fixAliases;
    protected String libraryPath;
    protected char[] password;

    /**
     * Creates a new {@link KeyStoreBuilder} instance.
     * 
     * @return {@link KeyStoreBuilder}
     */
    public static KeyStoreBuilder create()
    {
        return new KeyStoreBuilder();
    }

    protected KeyStoreBuilder()
    {
        type = KeyStore.getDefaultType();
        provider = null;
        path = null;
        fixAliases = false;
        libraryPath = null;
        password = null;
    }

    /**
     * Set the name of the security provider. Note that the list of registered providers may be retrieved via the
     * Security.getProviders() method.
     * 
     * @param provider the name of the provider
     * @see KeyStoreProvider
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setProvider(String provider)
    {
        this.provider = provider;
        return this;
    }

    /**
     * Set the type of keystore. Default is {@link KeyStore#getDefaultType()} See Appendix A in the <a href=
     * "../../../technotes/guides/security/crypto/CryptoSpec.html#AppA"> Java Cryptography Architecture API
     * Specification &amp; Reference </a> for information about standard keystore types.
     * 
     * @param type the type of keystore.
     * @see KeyStoreType
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setType(String type)
    {
        this.type = type;
        return this;
    }

    /**
     * Eliminates duplicate alias. Default is <code>false</code>. This parameter should only set to <code>true</code>
     * when the keystore provider is MSCAPI and the keystore contains duplicate aliases. More information about this
     * problem are described <a href="http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6672015">here</a>.
     * 
     * @param fixAliases when <code>true</code>, duplicate aliases will be eliminated, otherwise not
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setFixAliases(boolean fixAliases)
    {
        this.fixAliases = fixAliases;
        return this;
    }

    /**
     * Set the path to the keystore file. Default path is <code>null</code>.
     * 
     * @param path the path to the keystore file.
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setPath(String path)
    {
        this.path = path;
        return this;
    }

    /**
     * Set the path to the PKCS11-library. The default path is <code>null</code> (no special library).
     * 
     * @param libraryPath the path to the PKCS11-library (e.g. c:/PROGRA~2/ITSOLU~1/TRUSTW~1.2/32/itp11.dll)
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setLibraryPath(String libraryPath)
    {
        this.libraryPath = libraryPath;
        return this;
    }

    /**
     * Set the password to access the key store. Default is <code>null</code> (no password required).
     * 
     * @param password the password used to check the integrity of the key store, the password used to unlock the
     *            key store, or null
     * 
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setPassword(char[] password)
    {
        this.password = password;
        return this;
    }

    /**
     * Build a {@link KeyStore}.
     * 
     * @return {@link KeyStore}
     * 
     * @throws KeyStoreException if a KeyStoreSpi implementation for the specified type is not available from the
     *             specified provider.
     * @throws NoSuchProviderException if the specified provider is not registered in the security provider list.
     * @throws IllegalArgumentException if the provider name is null or empty.
     * @throws IllegalAccessException if the {@link #setFixAliases(boolean)} is set to <code>true</code>
     * @throws IOException if there is an I/O or format problem with the keystore data, if a password is required but
     *             not given, or if the given password was incorrect. If the error is due to a wrong password, the cause
     *             of the IOException should be an UnrecoverableKeyException
     * @throws NoSuchAlgorithmException if the algorithm used to check the integrity of the keystore cannot be found
     * @throws CertificateException if any of the certificates in the keystore could not be loaded
     */
    public KeyStore build() throws KeyStoreException, NoSuchProviderException, IllegalAccessException, IOException,
            NoSuchAlgorithmException, CertificateException
    {
        KeyStore keyStore = null;
        
        if (libraryPath != null)
        	setUpPKCS11ProviderWithLibrary();

        if (provider != null)
            keyStore = KeyStore.getInstance(type, provider);
        else
            keyStore = KeyStore.getInstance(type);

        if (path != null)
            keyStore.load(new FileInputStream(path), password);
        else
            keyStore.load(null, password);

        if (fixAliases)
            fixKeyStoreAliases(keyStore);

        return keyStore;
    }

    private void setUpPKCS11ProviderWithLibrary() throws IOException
	{
    	String name = UUID.randomUUID().toString();
		
    	registerProvider(name, libraryPath);
    	
    	setType(PKCS11).setProvider("SunPKCS11-" + name);
	}

	private void registerProvider(String name, String library) throws IOException
    {
        String config = new StringBuilder()
        		.append("name = ").append(name).append("\n")
        		.append("library = ").append(library).append("\n")
        		.toString();

        InputStream inputStream = new ByteArrayInputStream(config.getBytes());

        @SuppressWarnings("restriction")
        sun.security.pkcs11.SunPKCS11 p = new sun.security.pkcs11.SunPKCS11(inputStream);
        Security.addProvider(p);
    }

    /**
     * This method eliminates duplicate alias when the keystore provider is MSCAPI and the type is Windows-My. More
     * information about this problem are described <a
     * href="http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6672015">here</a>.
     * 
     * @param keyStore {@link KeyStore}
     * @throws IllegalAccessException - if the fix can't processed
     */
    private void fixKeyStoreAliases(KeyStore keyStore) throws IllegalAccessException
    {
        Field field;
        KeyStoreSpi keyStoreVeritable;

        try
        {
            field = keyStore.getClass().getDeclaredField("keyStoreSpi");
            field.setAccessible(true);
            keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

            if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName()))
            {
                Collection<?> entries;
                String alias;
                String hashCode;
                X509Certificate[] certificates;

                field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
                field.setAccessible(true);
                entries = (Collection<?>) field.get(keyStoreVeritable);

                for (Object entry : entries)
                {
                    field = entry.getClass().getDeclaredField("certChain");
                    field.setAccessible(true);
                    certificates = (X509Certificate[]) field.get(entry);

                    hashCode = Integer.toString(certificates[0].hashCode());

                    field = entry.getClass().getDeclaredField("alias");
                    field.setAccessible(true);
                    alias = (String) field.get(entry);

                    if (!alias.equals(hashCode))
                        field.set(entry, alias.concat(" - ").concat(hashCode));
                }
            }
        }
        catch (Exception e)
        {
            throw new IllegalAccessException("fix keystore aliases failed!");
        }
    }

}
