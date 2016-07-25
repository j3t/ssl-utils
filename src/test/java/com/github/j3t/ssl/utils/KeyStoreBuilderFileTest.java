package com.github.j3t.ssl.utils;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.GeneralSecurityException;
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
public class KeyStoreBuilderFileTest
{
    private KeyStore keyStore;

    @Parameters
    public static Collection<Object[]> data() throws IllegalAccessException, GeneralSecurityException, IOException
    {
        return Arrays.asList(new Object[][] {
            { KeyStoreType.JKS, "/certs/client.jks", null }, // password required for private attributes (see KeyStoreBuilderIT)
            { KeyStoreType.PKCS12, "/certs/client.p12", "PtUPmi#o" } // password required
        });
    }
    
    public KeyStoreBuilderFileTest(String type, String path, String pwd) throws IllegalAccessException, GeneralSecurityException, IOException
    {
        keyStore = KeyStoreBuilder.create()
                .setPath(getClass().getResource(path).getFile())
                .setType(type)
                .setPassword(pwd == null ? null : pwd.toCharArray())
                .build();
    }
    
    @Test
    public void keyStoreShouldContainsOneAlias() throws Exception
    {
        String[] aliases = KeyStoreHelper.getAliases(keyStore);
        
        assertEquals(1, aliases.length);
    }

    @Test
    public void keyStoreShouldContainsClientAlias() throws Exception
    {
        String[] aliases = KeyStoreHelper.getAliases(keyStore);
        
        assertEquals("client", aliases[0]);
    }
    
    @Test
    public void clientCertificateShouldHaveOneKeyUsage() throws Exception
    {
        Certificate cert = keyStore.getCertificate("client");
        KeyUsage[] keyUsages = CertificateHelper.getKeyUsages(cert);
        
        assertEquals(1, keyUsages.length);
    }
    
    @Test
    public void clientCertificateShouldHaveKeyUsageDigitalSignature() throws Exception
    {
        Certificate cert = keyStore.getCertificate("client");
        KeyUsage[] keyUsages = CertificateHelper.getKeyUsages(cert);
        
        assertEquals(KeyUsage.DIGITAL_SIGNATURE, keyUsages[0]);
    }
    
}
