package com.github.j3t.ssl.utils.test;

import static org.junit.Assert.assertArrayEquals;

import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.github.j3t.ssl.utils.KeyStoreHelper;

@RunWith(Parameterized.class)
public class FixturesTrustStoreTest
{
    private KeyStore trustStore;
    private String[] aliases;

    public FixturesTrustStoreTest(KeyStore trustStore, String[] aliases)
    {
        this.trustStore = trustStore;
        this.aliases = aliases;
    }

    @Parameters
    public static Collection<Object[]> data()
    {
        return Arrays.asList(new Object[][] {
            {Fixtures.TRUSTSTORE_CLIENT, new String[]{"server"}}, 
            {Fixtures.TRUSTSTORE_SERVER, new String[]{"client"}}
            });
    }

    @Test
    public void testTrustStore() throws Exception
    {
        assertArrayEquals(aliases, KeyStoreHelper.getAliases(trustStore));
    }
}
