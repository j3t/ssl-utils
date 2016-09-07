package com.github.j3t.ssl.utils;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.ProviderException;

import org.junit.Test;

import com.github.j3t.ssl.utils.types.KeyStoreType;

public class KeyStoreBuilderTest
{
    @Test
    public void givenKeyStoreBuilderWithoutType_whenBuild_thenKeyStoreShouldRetunrsDefaultType() throws Exception
    {
        assertEquals(KeyStore.getDefaultType(), KeyStoreBuilder.create().build().getType());
    }

    @Test(expected = KeyStoreException.class)
    public void givenKeyStoreBuilderWithUnsupportedType_whenBuild_thenExceptionShouldBeThrown() throws Exception
    {
        KeyStoreBuilder.create().setType("UNKNOWN_KEYSTORE_TYPE").build();
    }
    
    @Test(expected = ProviderException.class)
    public void givenKeyStoreBuilderWithUnsupportedLibrary_whenBuild_thenExceptionShouldBeThrown() throws Exception
    {
        File file = File.createTempFile("pkcs11-test", ".library");
        file.deleteOnExit();
        
        KeyStoreBuilder.create().setType(KeyStoreType.PKCS11).setLibraryPath(file.getPath()).build();
    }
}
