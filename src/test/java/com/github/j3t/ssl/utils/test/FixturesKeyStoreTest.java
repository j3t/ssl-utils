package com.github.j3t.ssl.utils.test;

import static com.github.j3t.ssl.utils.test.Fixtures.KEYSTORE_CLIENT;
import static com.github.j3t.ssl.utils.test.Fixtures.KEYSTORE_CLIENT_P12;
import static com.github.j3t.ssl.utils.test.Fixtures.KEYSTORE_EMPTY;
import static com.github.j3t.ssl.utils.test.Fixtures.KEYSTORE_MULTI;
import static com.github.j3t.ssl.utils.test.Fixtures.KEYSTORE_SERVER;
import static com.github.j3t.ssl.utils.test.Fixtures.KEYSTORE_UNKNOWN_CLIENT;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import static com.github.j3t.ssl.utils.types.KeyUsage.*;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.github.j3t.ssl.utils.CertificateHelper;
import com.github.j3t.ssl.utils.KeyStoreHelper;
import com.github.j3t.ssl.utils.types.KeyUsage;

@RunWith(Parameterized.class)
public class FixturesKeyStoreTest
{
    private KeyStore keyStore;
    private String[] aliases;
    private KeyUsage[][] keyUsages;

    public FixturesKeyStoreTest(KeyStore keyStore, String[] aliases, KeyUsage[][] keyUsages)
    {
        this.keyStore = keyStore;
        this.aliases = aliases;
        this.keyUsages = keyUsages;
    }

    @Parameters
    public static Collection<Object[]> data()
    {
        return Arrays.asList(new Object[][] {
            {KEYSTORE_CLIENT, new String[]{"client"}, new KeyUsage[][]{{DIGITAL_SIGNATURE}}},
            {KEYSTORE_CLIENT_P12, new String[]{"client"}, new KeyUsage[][]{{DIGITAL_SIGNATURE}}},
            {KEYSTORE_EMPTY, new String[0], new KeyUsage[0][0]},
            {KEYSTORE_MULTI, new String[]{"client", "server"}, new KeyUsage[][]{{DIGITAL_SIGNATURE}, {KEY_CERT_SIGN, C_RL_SIGN}}},
            {KEYSTORE_SERVER, new String[]{"server"}, new KeyUsage[][]{{KEY_CERT_SIGN, C_RL_SIGN}}},
            {KEYSTORE_UNKNOWN_CLIENT, new String[]{"client"}, new KeyUsage[][]{{DIGITAL_SIGNATURE}}},
            });
    }

    @Test
    public void testKeyStore() throws Exception
    {
        String[] actualAliases = KeyStoreHelper.getAliases(keyStore);
        
        Arrays.sort(aliases);
        Arrays.sort(actualAliases);
        
        assertArrayEquals(aliases, actualAliases);
        
        for (int i = 0; i < aliases.length; i++)
        {
            Certificate certificate = keyStore.getCertificate(aliases[i]);
            KeyUsage[] actualKeyUsages = CertificateHelper.getKeyUsages(certificate);

            Arrays.sort(keyUsages[i]);
            Arrays.sort(actualKeyUsages);
            
            assertTrue(CertificateHelper.isValid(certificate));
            assertArrayEquals(keyUsages[i], actualKeyUsages);
        }
    }
}
