package com.github.j3t.ssl.utils;

import static com.github.j3t.ssl.utils.types.KeyStoreProvider.*;
import static com.github.j3t.ssl.utils.types.KeyStoreType.*;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

import java.security.KeyStore;

import org.junit.Before;
import org.junit.Test;

/**
 * Test key store building on MacOS.
 *
 * @author j3t
 */
public class KeyStoreBuilderAppleTest
{
    private KeyStoreBuilder builder;
    
    @Before
    public void setUp() throws Exception
    {
        assumeTrue("Operating System isn't MacOS!", EnvironmentHelper.isMac());
        
        builder = KeyStoreBuilder.create();
    }
    
    @Test
    public void givenAppleKeyStore_whenBuildOnMac_thenKeyStoreShouldBeNotNull() throws Exception
    {
        KeyStore keyStore = builder
                .setType(KEYCHAIN_STORE)
                .setProvider(APPLE)
                .build();
        
        assertNotNull(keyStore);
    }
    
}
