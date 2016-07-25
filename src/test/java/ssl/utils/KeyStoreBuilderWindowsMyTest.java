package ssl.utils;

import static org.junit.Assert.assertTrue;
import static ssl.utils.types.KeyStoreProvider.SUN_MSCAPI;
import static ssl.utils.types.KeyStoreType.WINDOWS_MY;

import java.security.KeyStore;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import ssl.utils.KeyStoreBuilder;
import ssl.utils.KeyStoreHelper;

@Ignore("required Windows OS with at least one certificate installed (certmgr.msc->own certificates)")
public class KeyStoreBuilderWindowsMyTest
{
    private KeyStoreBuilder builder;
    
    @Before
    public void setUp() throws Exception
    {
        builder = KeyStoreBuilder.create();
    }
    
    @Test
    public void keyStoreShouldContainsAtLeastOneAlias() throws Exception
    {
        KeyStore keyStore = builder
                .setType(WINDOWS_MY)
                .setProvider(SUN_MSCAPI)
                .build();
        
        assertTrue(KeyStoreHelper.getAliases(keyStore).length >= 1);
    }
    
    @Test
    public void keyStoreWithFixedAliasesShouldContainsAtLeastOneAlias() throws Exception
    {
        KeyStore keyStore = builder
                .setType(WINDOWS_MY)
                .setProvider(SUN_MSCAPI)
                .setFixAliases(true)
                .build();
        
        assertTrue(KeyStoreHelper.getAliases(keyStore).length >= 1);
    }
}
