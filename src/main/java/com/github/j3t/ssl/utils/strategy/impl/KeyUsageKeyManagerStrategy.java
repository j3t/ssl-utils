package com.github.j3t.ssl.utils.strategy.impl;

import java.security.KeyStore;

import com.github.j3t.ssl.utils.KeyStoreHelper;
import com.github.j3t.ssl.utils.strategy.KeyManagerStrategy;
import com.github.j3t.ssl.utils.types.KeyUsage;

/**
 * This implementation of {@link KeyManagerStrategy} choose the first alias found in the key store that has the required
 * key usages.
 *
 * @author j3t
 *
 */
public class KeyUsageKeyManagerStrategy implements KeyManagerStrategy
{
    
    private String[] aliases;

    public KeyUsageKeyManagerStrategy(KeyStore keyStore, KeyUsage... keyUsages)
    {
        aliases = KeyStoreHelper.getAliases(keyStore, keyUsages);
    }

    @Override
    public String chooseAlias()
    {
        return aliases.length == 0 ? null : aliases[0];
    }

}
