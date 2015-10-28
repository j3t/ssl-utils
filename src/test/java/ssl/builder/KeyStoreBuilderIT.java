package ssl.builder;

import static org.junit.Assert.assertEquals;

import java.security.KeyStore;
import java.security.KeyStoreException;

import org.junit.Test;

import ssl.builder.KeyStoreBuilder;

public class KeyStoreBuilderIT
{
    
    @Test
    public void testDefaultKeyStore() throws Exception
    {
        assertEquals(KeyStore.getDefaultType(), KeyStoreBuilder.create().build().getType());
    }

    @Test(expected = KeyStoreException.class)
    public void testCreateKeyStoreWithUnknownType() throws Exception
    {
        KeyStoreBuilder.create().setType("UNKNOWN_KEYSTORE_TYPE").build();
    }
}
