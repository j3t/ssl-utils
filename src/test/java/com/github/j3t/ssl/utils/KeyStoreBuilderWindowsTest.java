package com.github.j3t.ssl.utils;

import org.junit.Before;
import org.junit.Test;

import static com.github.j3t.ssl.utils.types.KeyStoreProvider.SUN_MSCAPI;
import static com.github.j3t.ssl.utils.types.KeyStoreType.WINDOWS_MY;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

/**
 * Requirements: Windows OS
 *
 * @author j3t
 */
public class KeyStoreBuilderWindowsTest {
    private KeyStoreBuilder builder;

    @Before
    public void setUp() throws Exception {
        assumeTrue("Operating System isn't Windows!", EnvironmentHelper.isWindows());

        builder = KeyStoreBuilder.create().setType(WINDOWS_MY).setProvider(SUN_MSCAPI);
    }

    @Test
    public void givenKeyStoreWithWindowsMyAndMSCAPI_whenBuildOnWindows_thenKeyStoreShouldBeNotNull() throws Exception {
        assertNotNull(builder.build());
    }

    @Test
    public void givenKeyStoreWithWindowsMyAndMSCAPIAndFixAliases_whenBuildOnWindows_thenKeyStoreShouldBeNotNull() throws Exception {
        assertNotNull(builder.setFixAliases(true).build());
    }
}
