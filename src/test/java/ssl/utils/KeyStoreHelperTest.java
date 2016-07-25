package ssl.utils;

import static org.junit.Assert.assertEquals;

import java.security.KeyStore;
import java.security.KeyStoreException;

import org.junit.Before;
import org.junit.Test;

import ssl.utils.KeyStoreBuilder;
import ssl.utils.KeyStoreHelper;
import ssl.utils.types.KeyUsage;

public class KeyStoreHelperTest
{
    private KeyStore keyStore;

    @Before
    public void setUp() throws Exception
    {
        keyStore = KeyStoreBuilder.create()
                .setPath(getClass().getResource("/server.jks").getFile())
                .build();
    }

    @Test(expected = NullPointerException.class)
    public void getAliasesShouldThrowExceptionWhenCalledWithoutKeyStore()
    {
        KeyStoreHelper.getAliases(null);
    }
    
    @Test
    public void getAliasesShouldReturnOneAliasWhenKeyStoreHasOneKey()
    {
        assertEquals(1, KeyStoreHelper.getAliases(keyStore).length);
    }

    @Test(expected = NullPointerException.class)
    public void getAliasesWithKeyUsageShouldThrowExceptionWhenKeyUsagesIsNull()
    {
        KeyStoreHelper.getAliases(keyStore, (KeyUsage[]) null);
    }
    
    @Test(expected = NullPointerException.class)
    public void getAliasesWithKeyUsageShouldThrowExceptionWhenKeyStoreIsNull()
    {
        KeyStoreHelper.getAliases(null, KeyUsage.DATA_ENCIPHERMENT);
    }
    
    @Test
    public void getAliasesWithKeyUsageShouldReturnEmptyArrayWhenNoKeyHasThisKeyUsage()
    {
        assertEquals(0, KeyStoreHelper.getAliases(keyStore, KeyUsage.DATA_ENCIPHERMENT).length);
    }
    
    @Test
    public void getAliasesWithKeyUsageShouldReturnOneAliasWhenOneKeyHasThisKeyUsage() throws KeyStoreException
    {
        assertEquals(1, KeyStoreHelper.getAliases(keyStore, KeyUsage.C_RL_SIGN).length);
        assertEquals(1, KeyStoreHelper.getAliases(keyStore, KeyUsage.KEY_CERT_SIGN).length);
    }
    
    @Test
    public void getAliasesWithTwoKeyUsagesShouldReturnOneAliasWhenOneKeyHasThisTwoKeyUsages()
    {
        assertEquals(1, KeyStoreHelper.getAliases(keyStore, KeyUsage.KEY_CERT_SIGN, KeyUsage.C_RL_SIGN).length);
    }
    
    @Test
    public void getAliasesWithTwoKeyUsagesShouldReturnEmptyResultWhenNoKeyHasThisTwoKeyUsages()
    {
        assertEquals(0, KeyStoreHelper.getAliases(keyStore, KeyUsage.DATA_ENCIPHERMENT, KeyUsage.C_RL_SIGN).length);
    }
}
