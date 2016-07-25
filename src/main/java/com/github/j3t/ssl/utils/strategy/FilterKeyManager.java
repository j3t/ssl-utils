
package com.github.j3t.ssl.utils.strategy;


import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link X509KeyManager} that allows control which alias/key is used during authentication. Whenever
 * an alias/key is requested, the given {@link TrustManagerStrategy} will be consulted. Depending on the result, the
 * request will be delegated to the key manager of the current context or not.
 * 
 * @see KeyManagerStrategy
 * 
 * @author j3t
 *
 */
public class FilterKeyManager implements X509KeyManager
{
    private static final Logger LOGGER = LoggerFactory.getLogger(FilterKeyManager.class);

    private X509KeyManager keyManager;
    private KeyManagerStrategy chooseAliasListener;

    /**
     * Creates an instance of {@link FilterKeyManager}.
     * 
     * @param keyManager the underlying {@link X509KeyManager}
     * @param chooseAliasListener the {@link KeyManagerStrategy}
     */
    public FilterKeyManager(X509KeyManager keyManager, KeyManagerStrategy chooseAliasListener)
    {
        this.keyManager = keyManager;
        this.chooseAliasListener = chooseAliasListener;
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        String alias = chooseAliasListener.chooseAlias();

        if (alias == null)
            alias = keyManager.chooseClientAlias(keyTypes, issuers, socket);

        LOGGER.debug("choosen alias: {}", alias);

        return alias;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        String alias = chooseAliasListener.chooseAlias();

        if (alias == null)
            alias = keyManager.chooseServerAlias(keyType, issuers, socket);

        LOGGER.debug("choosen alias: {}", alias);

        return alias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String keyType)
    {
        return keyManager.getCertificateChain(keyType);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return keyManager.getClientAliases(keyType, issuers);
    }

    @Override
    public PrivateKey getPrivateKey(String keyType)
    {
        return keyManager.getPrivateKey(keyType);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        return keyManager.getServerAliases(keyType, issuers);
    }

}
