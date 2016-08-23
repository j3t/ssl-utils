package com.github.j3t.ssl.utils.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.github.j3t.ssl.utils.CertificateHelper;
import com.github.j3t.ssl.utils.KeyStoreBuilder;
import com.github.j3t.ssl.utils.KeyStoreHelper;
import com.github.j3t.ssl.utils.types.KeyStoreType;
import com.github.j3t.ssl.utils.types.KeyUsage;

@RunWith(Parameterized.class)
public class ResourceKeyStoreTest
{
    private String keyStoreType;
    private String path;
    private String[] aliases;
    private KeyUsage[][] keyUsages;
    private String password;

    public ResourceKeyStoreTest(String keyStoreType, String path, String password, String[] aliases, KeyUsage[][] keyUsages)
    {
        this.keyStoreType = keyStoreType;
        this.path = path;
        this.password = password;
        this.aliases = aliases;
        this.keyUsages = keyUsages;
    }

    @Parameters
    public static Collection<Object[]> data()
    {
        return Arrays.asList(new Object[][] {
            {KeyStoreType.JKS, "/certs/client.jks", "PtUPmi#o", new String[]{"client"}, new KeyUsage[][]{{KeyUsage.DIGITAL_SIGNATURE}}},
            {KeyStoreType.PKCS12, "/certs/client.p12", "PtUPmi#o", new String[]{"client"}, new KeyUsage[][]{{KeyUsage.DIGITAL_SIGNATURE}}},
            {KeyStoreType.JKS, "/certs/empty.jks", "changeit", new String[0], new KeyUsage[0][0]},
            {KeyStoreType.JKS, "/certs/multi.jks", "changeit", new String[]{"client", "server"}, new KeyUsage[][]{{KeyUsage.DIGITAL_SIGNATURE}, {KeyUsage.KEY_CERT_SIGN, KeyUsage.C_RL_SIGN}}},
            {KeyStoreType.JKS, "/certs/server.jks", "EC\\sEOoY", new String[]{"server"}, new KeyUsage[][]{{KeyUsage.KEY_CERT_SIGN, KeyUsage.C_RL_SIGN}}},
            {KeyStoreType.JKS, "/certs/unknown-client.jks", "changeit", new String[]{"client"}, new KeyUsage[][]{{KeyUsage.DIGITAL_SIGNATURE}}},
            });
    }

    @Test
    public void testKeyStore() throws Exception
    {
        KeyStore keyStore = KeyStoreBuilder.create()
                .setType(keyStoreType)
                .setPath(ResourceKeyStoreTest.class.getResource(path).getFile())
                .setPassword(password.toCharArray())
                .build();
        
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
