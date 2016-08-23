package com.github.j3t.ssl.utils.test;

import static org.junit.Assert.assertArrayEquals;

import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.github.j3t.ssl.utils.KeyStoreBuilder;
import com.github.j3t.ssl.utils.KeyStoreHelper;
import com.github.j3t.ssl.utils.types.KeyStoreType;

@RunWith(Parameterized.class)
public class ResourceTrustStoreTest
{
    private String name;
    private String[] aliases;

    public ResourceTrustStoreTest(String name, String[] aliases)
    {
        this.name = name;
        this.aliases = aliases;
    }

    @Parameters
    public static Collection<Object[]> data()
    {
        return Arrays.asList(new Object[][] {
            {"/certs/client-trust.jks", new String[]{"server"}}, 
            {"/certs/server-trust.jks", new String[]{"client"}}
            });
    }

    @Test
    public void testTrustStore() throws Exception
    {
        KeyStore keyStore = KeyStoreBuilder.create()
                .setType(KeyStoreType.JKS)
                .setPath(ResourceTrustStoreTest.class.getResource(name).getFile())
                .build();
        
        assertArrayEquals(aliases, KeyStoreHelper.getAliases(keyStore));
    }
}
