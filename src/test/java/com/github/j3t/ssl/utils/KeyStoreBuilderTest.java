package com.github.j3t.ssl.utils;

import com.github.j3t.ssl.utils.types.KeyStoreType;
import org.junit.Test;

import java.io.File;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.ProviderException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class KeyStoreBuilderTest {
    @Test(expected = IllegalStateException.class)
    public void givenKeyStoreBuilderWithInvalidLibraryPath_whenBuildUnsecure_thenExceptionShouldBeThrown() throws Exception {
        KeyStoreBuilder.create().setLibraryPath("/bla/foo").buildUnsecure();
    }

    @Test
    public void givenKeyStoreBuilder_whenSetPasswordStringWithNullInvoked_thenKeyStoreBuilderShouldBeReturned() throws Exception {
        assertNotNull(KeyStoreBuilder.create().setPassword((String) null));
    }

    @Test
    public void givenKeyStoreBuilderWithoutType_whenBuild_thenKeyStoreShouldBeReturnedDefaultType() throws Exception {
        assertEquals(KeyStore.getDefaultType(), KeyStoreBuilder.create().build().getType());
    }

    @Test(expected = KeyStoreException.class)
    public void givenKeyStoreBuilderWithUnsupportedType_whenBuild_thenExceptionShouldBeThrown() throws Exception {
        KeyStoreBuilder.create().setType("UNKNOWN_KEYSTORE_TYPE").build();
    }

    @Test(expected = ProviderException.class)
    public void givenKeyStoreBuilderWithUnsupportedLibrary_whenBuild_thenExceptionShouldBeThrown() throws Exception {
        File file = File.createTempFile("pkcs11-test", ".library");
        file.deleteOnExit();

        KeyStoreBuilder.create().setType(KeyStoreType.PKCS11).setLibraryPath(file.getPath()).build();
    }
}
