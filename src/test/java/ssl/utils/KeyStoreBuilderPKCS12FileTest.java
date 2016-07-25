package ssl.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.KeyStore;
import java.security.cert.Certificate;

import org.junit.Before;
import org.junit.Test;

import ssl.utils.CertificateHelper;
import ssl.utils.KeyStoreBuilder;
import ssl.utils.KeyStoreHelper;
import ssl.utils.types.KeyStoreType;
import ssl.utils.types.KeyUsage;

public class KeyStoreBuilderPKCS12FileTest
{
    private KeyStore keyStore;

    @Before
    public void setUp() throws Exception
    {
        keyStore = KeyStoreBuilder.create()
                .setPath(getClass().getResource("/client.p12").getFile())
                .setType(KeyStoreType.PKCS12)
                .setPassword("PtUPmi#o".toCharArray())
                .build();
    }
    
    @Test
    public void keyStoreShouldContainsClientAlias() throws Exception
    {
        String[] aliases = KeyStoreHelper.getAliases(keyStore);
        
        assertEquals(1, aliases.length);
        assertEquals("client", aliases[0]);
    }

    @Test
    public void certificateShouldSupportKeyUsageDigitalSignature() throws Exception
    {
        Certificate cert = keyStore.getCertificate("client");
        
        assertEquals(1, CertificateHelper.getKeyUsages(cert).length);
        assertTrue(CertificateHelper.isKeyUsagePresent(cert, KeyUsage.DIGITAL_SIGNATURE));
    }
}
