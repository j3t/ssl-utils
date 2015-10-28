
package ssl.builder;


import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;

import ssl.helper.TrustManagerHelper;
import ssl.strategy.AliasSelectionStrategy;
import ssl.strategy.StrategyKeyManager;

/**
 * A builder pattern style {@link SSLContext} factory, especially for Volkswagen PKI.
 * 
 * @author j3t
 */
public class SSLContextBuilder
{
    private KeyStore keyStore;
    private char[] keyStorePassword;
    private AliasSelectionStrategy aliasSelectionStrategy;
    private SecureRandom secureRandomGenerator;
    private TrustManager[] trustManagers;
    private String algorithm;
    private String protocol;

    /**
     * Creates a new {@link SSLContextBuilder} instance.
     * 
     * @return {@link SSLContextBuilder}
     */
    public static SSLContextBuilder create()
    {
        return new SSLContextBuilder();
    }

    protected SSLContextBuilder()
    {
        keyStore = null;
        keyStorePassword = null;
        aliasSelectionStrategy = null;
        secureRandomGenerator = new SecureRandom();
        trustManagers = null;
        algorithm = KeyManagerFactory.getDefaultAlgorithm();
        protocol = "TLS";
    }

    /**
     * Set the source of randomness for the number generator of the {@link SSLContext}.
     * 
     * @param secureRandomGenerator the source of randomness for the number generator, or <code>null</code>
     * 
     * @return {@link SSLContextBuilder}
     */
    public SSLContextBuilder setSecureRandomGenerator(SecureRandom secureRandomGenerator)
    {
        this.secureRandomGenerator = secureRandomGenerator;
        return this;
    }

    public SSLContextBuilder setTrustManagers(TrustManager[] trustManagers)
    {
        this.trustManagers = trustManagers;
        return this;
    }

    public SSLContextBuilder setKeyStore(KeyStore keyStore)
    {
        this.keyStore = keyStore;
        return this;
    }
    
    public SSLContextBuilder setKeyStorePassword(char[] keyStorePassword)
    {
        this.keyStorePassword = keyStorePassword;
        return this;
    }

    public SSLContextBuilder setAlgorithm(String algorithm)
    {
        this.algorithm = algorithm;
        return this;
    }

    public SSLContextBuilder setProtocol(String protocol)
    {
        this.protocol = protocol;
        return this;
    }
    
    public SSLContextBuilder setAliasSelectionStrategy(AliasSelectionStrategy aliasSelectionStrategy)
    {
        this.aliasSelectionStrategy = aliasSelectionStrategy;
        return this;
    }

    public SSLContext build() throws GeneralSecurityException, IOException
    {
        SSLContext ctx = SSLContext.getInstance(protocol);
        ctx.init(createKeyManagers(), createTrustManagers(), secureRandomGenerator);
        
        return ctx;
    }

    protected TrustManager[] createTrustManagers()
    {
        return trustManagers == null ? TrustManagerHelper.createWindowsRootTrustManagers() : trustManagers;
    }

    protected KeyManager[] createKeyManagers() throws GeneralSecurityException
    {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
        kmf.init(keyStore, keyStorePassword);
        
        KeyManager[] keyManagers = kmf.getKeyManagers();

        if (aliasSelectionStrategy != null)
            keyManagers = proxyWithStrategyKeyManager(keyManagers);
            
        return keyManagers;
    }

    protected KeyManager[] proxyWithStrategyKeyManager(KeyManager[] keyManagers)
    {
        KeyManager[] kms = new KeyManager[keyManagers.length];

        for (int i = 0; i < keyManagers.length; i++)
        {
            KeyManager keyManager = keyManagers[i];

            if (keyManager instanceof X509KeyManager)
                kms[i] = new StrategyKeyManager((X509KeyManager) keyManager, aliasSelectionStrategy);

            else
                kms[i] = keyManager;
        }

        return kms;
    }


}
