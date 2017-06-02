package com.github.j3t.ssl.utils;

import com.github.j3t.ssl.utils.types.KeyStoreType;
import com.github.j3t.ssl.utils.types.KeyUsage;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyStore;
import java.security.cert.Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class KeyStoreBuilderPKCS12FileTest {
    private KeyStore keyStore;

    @Before
    public void setUp() throws Exception {
        keyStore = KeyStoreBuilder.create()
                .setPath(getClass().getResource("/certs/client.p12").getFile())
                .setType(KeyStoreType.PKCS12)
                .setPassword("PtUPmi#o".toCharArray())
                .build();
    }

    @Test
    public void keyStoreShouldContainsClientAlias() throws Exception {
        String[] aliases = KeyStoreHelper.getAliases(keyStore);

        assertEquals(1, aliases.length);
        assertEquals("client", aliases[0]);
    }

    @Test
    public void certificateShouldSupportKeyUsageDigitalSignature() throws Exception {
        Certificate cert = keyStore.getCertificate("client");

        assertEquals(1, CertificateHelper.getKeyUsages(cert).length);
        assertTrue(CertificateHelper.isKeyUsagePresent(cert, KeyUsage.DIGITAL_SIGNATURE));
    }
}
