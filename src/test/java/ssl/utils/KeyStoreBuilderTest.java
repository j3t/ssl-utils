package ssl.utils;

import static org.junit.Assert.assertEquals;

import java.security.KeyStore;
import java.security.KeyStoreException;

import org.junit.Test;

import ssl.utils.KeyStoreBuilder;

public class KeyStoreBuilderTest
{
    
    @Test
    public void keyStoreWithUndefinedTypeShouldReturnDefaultType() throws Exception
    {
        assertEquals(KeyStore.getDefaultType(), KeyStoreBuilder.create().build().getType());
    }

    @Test(expected = KeyStoreException.class)
    public void buildKeyStoreWithUnknownTypeShouldThrowException() throws Exception
    {
        KeyStoreBuilder.create().setType("UNKNOWN_KEYSTORE_TYPE").build();
    }
}
