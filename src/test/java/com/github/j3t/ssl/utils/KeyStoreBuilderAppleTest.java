package com.github.j3t.ssl.utils;

import org.junit.Before;
import org.junit.Test;

import java.security.KeyStore;

import static com.github.j3t.ssl.utils.types.KeyStoreProvider.APPLE;
import static com.github.j3t.ssl.utils.types.KeyStoreType.KEYCHAIN_STORE;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

/**
 * Test key store building on MacOS.
 *
 * @author j3t
 */
public class KeyStoreBuilderAppleTest {
    private KeyStoreBuilder builder;

    @Before
    public void setUp() throws Exception {
        assumeTrue("Operating System isn't MacOS!", EnvironmentHelper.isMac());

        builder = KeyStoreBuilder.create();
    }

    @Test
    public void testKeyStoreBuilderWithDefaultMacOSKeyStore() throws Exception {
        // given KeyStoreBuilder with default MacOS key store
        KeyStore keyStore = builder
                .setType(KEYCHAIN_STORE)
                .setProvider(APPLE)
                .build();
        // when build is finished
        // then key store should be created
        assertNotNull(keyStore);
    }

}
