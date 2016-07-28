
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
public class StrategyKeyManager implements X509KeyManager
{
    private static final Logger LOGGER = LoggerFactory.getLogger(StrategyKeyManager.class);

    private X509KeyManager keyManager;
    private KeyManagerStrategy strategy;

    /**
     * Creates an instance of {@link StrategyKeyManager}.
     * 
     * @param keyManager the underlying {@link X509KeyManager}
     * @param strategy the {@link KeyManagerStrategy}
     */
    public StrategyKeyManager(X509KeyManager keyManager, KeyManagerStrategy strategy)
    {
        this.keyManager = keyManager;
        this.strategy = strategy;
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        String alias = strategy.chooseAlias();

        if (alias == null)
            alias = keyManager.chooseClientAlias(keyTypes, issuers, socket);

        LOGGER.debug("choosen alias: {}", alias);

        return alias;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        String alias = strategy.chooseAlias();

        if (alias == null)
            alias = keyManager.chooseServerAlias(keyType, issuers, socket);

        LOGGER.debug("choosen alias: {}", alias);

        return alias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias)
    {
        return keyManager.getCertificateChain(alias);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return keyManager.getClientAliases(keyType, issuers);
    }

    @Override
    public PrivateKey getPrivateKey(String alias)
    {
        return keyManager.getPrivateKey(alias);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        return keyManager.getServerAliases(keyType, issuers);
    }

}
