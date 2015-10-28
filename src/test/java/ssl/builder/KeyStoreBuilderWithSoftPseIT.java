package ssl.builder;

import static org.junit.Assert.assertTrue;
import static ssl.KeyStoreType.PKCS12;

import java.io.FileNotFoundException;
import java.security.KeyStore;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import ssl.builder.KeyStoreBuilder;
import ssl.helper.KeyStoreHelper;

public class KeyStoreBuilderWithSoftPseIT
{
    private KeyStoreBuilder builder;

    @Before
    public void setUp() throws Exception
    {
        builder = KeyStoreBuilder.create().setType(PKCS12);
    }

    @Ignore("soft pse reqired")
    @Test
    public void keyStoreShouldContainsAtLeastOneAlias() throws Exception
    {
        KeyStore keyStore = builder
                .setType(PKCS12)
                .setPath("/path/to/cert.p12")
                .build();
        
        assertTrue(KeyStoreHelper.getAliases(keyStore).length >= 1);
    }
    
    @Test(expected = FileNotFoundException.class)
    public void testCreatePKCS12KeyStoreWithoutUnknownCertificate() throws Exception
    {
        builder.setType(PKCS12).setPath("/bla").build();
    }
}
