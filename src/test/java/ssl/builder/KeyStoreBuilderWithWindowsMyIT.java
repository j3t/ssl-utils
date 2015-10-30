package ssl.builder;

import static org.junit.Assert.assertTrue;
import static ssl.KeyStoreProvider.SUNMSCAPI;
import static ssl.KeyStoreType.WINDOWS_MY;

import java.security.KeyStore;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import ssl.builder.KeyStoreBuilder;
import ssl.helper.KeyStoreHelper;

@Ignore("windows-my keystore with certificates required")
public class KeyStoreBuilderWithWindowsMyIT
{
    
    private KeyStoreBuilder builder;

    @Before
    public void setUp() throws Exception
    {
        builder = KeyStoreBuilder.create();
    }

    @Test
    public void keyStoreWindowsMyShouldContainsAtLeastOneAlias() throws Exception
    {
        KeyStore keyStore = builder
                .setType(WINDOWS_MY)
                .setProvider(SUNMSCAPI)
                .build();
        
        assertTrue(KeyStoreHelper.getAliases(keyStore).length >= 1);
    }
    
    @Test
    public void keyStoreWindowsMyWithFixedAliasesShouldContainsAtLeastThreeAliases() throws Exception
    {
        KeyStore keyStore = builder
                .setType(WINDOWS_MY)
                .setProvider(SUNMSCAPI)
                .setFixAliases(true)
                .build();
        
        assertTrue(KeyStoreHelper.getAliases(keyStore).length >= 3);
    }
    
}
