package com.github.j3t.ssl.utils;

import static org.junit.Assert.*;

import java.security.KeyStore;
import java.security.KeyStoreException;

import org.junit.Before;
import org.junit.Test;

import com.github.j3t.ssl.utils.types.KeyUsage;

public class KeyStoreHelperTest
{
    private KeyStore keyStore;
    private KeyStore uninitializedKeyStore;
    private KeyStore emptyKeyStore;
    private KeyStore multiKeyStore;

    @Before
    public void setUp() throws Exception
    {
        keyStore = KeyStoreBuilder.create()
                .setPath(getClass().getResource("/certs/server.jks").getFile())
                .build();
        
        uninitializedKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        
        emptyKeyStore = KeyStoreBuilder.create()
                .setPath(getClass().getResource("/certs/empty.jks").getFile())
                .build();
        
        multiKeyStore = KeyStoreBuilder.create()
                .setPath(getClass().getResource("/certs/multi.jks").getFile())
                .build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void getAliasesShouldThrowExceptionWhenKeyStoreIsNull()
    {
        KeyStoreHelper.getAliases(null);
    }
    
    @Test
    public void getAliasesShouldReturnOneAliasWhenKeyStoreHasOneKey()
    {
        assertEquals(1, KeyStoreHelper.getAliases(keyStore).length);
    }
    
    @Test(expected = IllegalStateException.class)
    public void getAliasesShouldThrowExceptionWhenKeyStoreIsNotInitialized() throws Exception
    {
        KeyStoreHelper.getAliases(uninitializedKeyStore);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getAliasesWithKeyUsageShouldThrowExceptionWhenKeyUsagesIsNull()
    {
        KeyStoreHelper.getAliases(keyStore, (KeyUsage[]) null);
    }
    
    @Test
    public void getAliasesWithKeyUsageShouldReturnEmptyResultWhenKeyUsagesEmpty()
    {
        assertEquals(0, KeyStoreHelper.getAliases(keyStore, new KeyUsage[0]).length);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void getAliasesWithKeyUsageShouldThrowExceptionWhenKeyStoreIsNull()
    {
        KeyStoreHelper.getAliases(null, KeyUsage.DATA_ENCIPHERMENT);
    }
    
    @Test(expected = IllegalStateException.class)
    public void getAliasesWithKeyUsageShouldThrowExceptionWhenKeyStoreIsNotInitialized() throws Exception
    {
        KeyStoreHelper.getAliases(uninitializedKeyStore, KeyUsage.DATA_ENCIPHERMENT);
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
    
    @Test
    public void toStringShouldReturnStringNotEmptyWhenKeyStoreIsNotNull()
    {
        assertFalse(KeyStoreHelper.toString(keyStore).isEmpty());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void toStringShouldThrowExceptionWhenKeyStoreIsNull()
    {
        KeyStoreHelper.toString(null);
    }
    
    @Test(expected = IllegalStateException.class)
    public void toStringShouldThrowExceptionWhenKeyStoreIsNotInitialzed() throws Exception
    {
        KeyStoreHelper.toString(uninitializedKeyStore);
    }
    
    @Test
    public void toStringShouldReturnEmptyStringWhenKeyStoreIsEmpty() throws Exception
    {
        assertEquals("keyStore is empty", KeyStoreHelper.toString(emptyKeyStore));
    }
    
    @Test(expected = IllegalStateException.class)
    public void toStringByAliasShouldThrowExceptionWhenKeyStoreIsNotInitialzed() throws Exception
    {
        KeyStoreHelper.toStringByAlias(uninitializedKeyStore, "client");
    }
    
    @Test
    public void givenKeyStoreWithMultipleKeys_whenToStringByAliasWithTwoAliasesExecuted_thenResultShouldContainsNewLine() throws Exception
    {
        assertTrue(KeyStoreHelper.toStringByAlias(multiKeyStore, "client", "server").contains("\r\n"));
    }
}
